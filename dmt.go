// This file is part of Direct MinIO Tunnel
// Copyright (c) 2020 MinIO, Inc.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	xhttp "github.com/minio/minio/cmd/http"
	"github.com/minio/minio/cmd/rest"
	"golang.org/x/net/http2"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/kubernetes"
	k8srest "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
)

// ParsePublicCertFile - parses public cert into its *x509.Certificate equivalent.
func ParsePublicCertFile(certFile string) (x509Certs []*x509.Certificate, err error) {
	// Read certificate file.
	var data []byte
	if data, err = ioutil.ReadFile(certFile); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	// Trimming leading and tailing white spaces.
	data = bytes.TrimSpace(data)

	// Parse all certs in the chain.
	current := data
	for len(current) > 0 {
		var pemBlock *pem.Block
		if pemBlock, current = pem.Decode(current); pemBlock == nil {
			return nil, fmt.Errorf("could not read PEM block from file %s", certFile)
		}

		var x509Cert *x509.Certificate
		if x509Cert, err = x509.ParseCertificate(pemBlock.Bytes); err != nil {
			return nil, err
		}

		x509Certs = append(x509Certs, x509Cert)
	}

	if len(x509Certs) == 0 {
		return nil, fmt.Errorf("empty public certificate file %s", certFile)
	}

	return x509Certs, nil
}

var (
	caCert string
	tlsDir string

	globalDNSCache        *xhttp.DNSCache
	globalTenantAccessMap *tenantAccessMap
)

func init() {
	flag.StringVar(&tlsDir, "tls-dir", "/etc/dmt/tls", "TLS certificate directories")
	flag.StringVar(&caCert, "ca-cert", "/etc/dmt/ca.crt", "CA certificates")
	globalDNSCache = xhttp.NewDNSCache(3*time.Second, 10*time.Second)
	globalTenantAccessMap = newTenantAccessMap()
}

func newInternodeHTTPTransport(tlsConfig *tls.Config, dialTimeout time.Duration) func() *http.Transport {
	// For more details about various values used here refer
	// https://golang.org/pkg/net/http/#Transport documentation
	tr := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           xhttp.DialContextWithDNSCache(globalDNSCache, xhttp.NewInternodeDialContext(dialTimeout)),
		MaxIdleConnsPerHost:   1024,
		IdleConnTimeout:       15 * time.Second,
		ResponseHeaderTimeout: 3 * time.Minute, // Set conservative timeouts for MinIO internode.
		TLSHandshakeTimeout:   15 * time.Second,
		ExpectContinueTimeout: 15 * time.Second,
		TLSClientConfig:       tlsConfig,
		// Go net/http automatically unzip if content-type is
		// gzip disable this feature, as we are always interested
		// in raw stream.
		DisableCompression: true,
	}

	if tlsConfig != nil {
		http2.ConfigureTransport(tr)
	}

	return func() *http.Transport {
		return tr
	}
}

const (
	dmtConfigMapName = "dmt-config"
	dmtConfigMapKey  = "routes.json"

	routeConfigVersion = "1"
)

// Current route configuration version '1'
//
// {
//     "version": "1",
//     "routes": {
//         "0HHZW0BSUIK3TGCF": "backend-1:9000",
//         "1OIGLFDMYMWIJCFV": "backend-2:9000",
//         "2S2UPSUO4L4XMTU0": "backend-3:9000",
//         "4103GYZD1OFNTL3Y": "backend-4:9000",
//         "4QW2BNRBPGSUP24Z": "backend-5:9000"
//     }
// }
type routeConfigV1 struct {
	Version string            `json:"version"`
	Routes  map[string]string `json:"routes"`
}

func loadConfiguration(rules string) (kv map[string]string, err error) {
	var rcfg = routeConfigV1{}
	if err = json.Unmarshal([]byte(rules), &rcfg); err != nil {
		return nil, err
	}
	switch rcfg.Version {
	case routeConfigVersion:
	default:
		return nil, fmt.Errorf("unexpected routes config version %s", rcfg.Version)
	}
	return rcfg.Routes, nil
}

func uponConfigUpdate(oldObj interface{}, newObj interface{}) {
	cfgMap := newObj.(*v1.ConfigMap)
	if cfgMap.ObjectMeta.Name == dmtConfigMapName {
		rules, ok := cfgMap.Data[dmtConfigMapKey]
		if !ok {
			return
		}
		kv, err := loadConfiguration(rules)
		if err != nil {
			log.Printf("failed to load rules from %s: (%s)\n", dmtConfigMapKey, err)
			return
		}
		globalTenantAccessMap.Update(kv)
	}
}

func getNamespace() string {
	// We assume'dmt' is running inside a k8s pod and extract the
	// current namespace from the /var/run/secrets/kubernetes.io/serviceaccount/namespace file
	return func() string {
		ns, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/namespace")
		if err != nil {
			return "default"
		}
		return string(ns)
	}()
}

var namespace = getNamespace()

func loadTenantAccessMap(k8sClient *kubernetes.Clientset) (map[string]string, error) {
	cfgMap, err := k8sClient.CoreV1().ConfigMaps(namespace).Get(dmtConfigMapName, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	v, ok := cfgMap.Data[dmtConfigMapKey]
	if !ok {
		return nil, fmt.Errorf("missing %s from config map, please check your deployment config", dmtConfigMapKey)
	}
	return loadConfiguration(v)
}

func runInformer(k8sClient *kubernetes.Clientset) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	factory := informers.NewSharedInformerFactoryWithOptions(k8sClient, 0, informers.WithNamespace(namespace))
	log.Println("Start dmt configMap informer on namespace", namespace)

	cfgMapInformer := factory.Core().V1().ConfigMaps().Informer()
	cfgMapInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		UpdateFunc: uponConfigUpdate,
	})

	go cfgMapInformer.Run(ctx.Done())

	// wait for the initial synchronization of the local cache.
	if !cache.WaitForCacheSync(ctx.Done(), cfgMapInformer.HasSynced) {
		panic(fmt.Errorf("failed to sync"))
	}

	<-ctx.Done()
}

// Secure Go implementations of modern TLS ciphers
// The following ciphers are excluded because:
//  - RC4 ciphers:              RC4 is broken
//  - 3DES ciphers:             Because of the 64 bit blocksize of DES (Sweet32)
//  - CBC-SHA256 ciphers:       No countermeasures against Lucky13 timing attack
//  - CBC-SHA ciphers:          Legacy ciphers (SHA-1) and non-constant time
//                              implementation of CBC.
//                              (CBC-SHA ciphers can be enabled again if required)
//  - RSA key exchange ciphers: Disabled because of dangerous PKCS1-v1.5 RSA
//                              padding scheme. See Bleichenbacher attacks.
var secureCipherSuites = []uint16{
	tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
	tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
}

// Go only provides constant-time implementations of Curve25519 and NIST P-256 curve.
var secureCurves = []tls.CurveID{tls.X25519, tls.CurveP256}

// dmt has support for multiple certificates. It expects the following structure:
//  /etc/dmt/tls/
//   ├─ example.com/
//   │   │
//   │   ├─ public.crt
//   │   └─ private.key
//   └─ foobar.org/
//      │
//      ├─ public.crt
//      └─ private.key
//   ...
//
// Therefore, we read all filenames in the cert directory and check
// for each directory whether it contains a public.crt and private.key.
// If so, we try to add it to certs in *http.Server* config.
// NOTE: Directories just need to be named there is no requirement
// on the right name or domain related to the certs.
func loadTLSCerts(dirname string) ([]tls.Certificate, error) {
	dirs, err := ioutil.ReadDir(dirname)
	if err != nil {
		return nil, err
	}
	var certs []tls.Certificate
	for _, dir := range dirs {
		// Regular file types are all ignored.
		if dir.IsDir() {
			cert, err := tls.LoadX509KeyPair(filepath.Join(dirname, dir.Name(), "public.crt"),
				filepath.Join(dirname, dir.Name(), "private.key"))
			if err != nil {
				return nil, err
			}
			certs = append(certs, cert)
		}
	}
	return certs, nil
}

func main() {
	flag.Parse()

	// Set system to maximum resources possible
	setMaxResources()

	defer globalDNSCache.Stop()

	certs, err := loadTLSCerts(tlsDir)
	if err != nil {
		log.Fatalln(err)
	}

	caCerts, err := ParsePublicCertFile(caCert)
	if err != nil {
		log.Fatalln(err)
	}

	k8sConfig, err := k8srest.InClusterConfig()
	if err != nil {
		log.Fatalln(err)
	}

	k8sClient, err := kubernetes.NewForConfig(k8sConfig)
	if err != nil {
		log.Fatalln(err)
	}

	// Load rules for the first tme
	kv, err := loadTenantAccessMap(k8sClient)
	if err != nil {
		log.Fatalln(err)
	}
	globalTenantAccessMap.Update(kv)

	// Start k8s informer
	go runInformer(k8sClient)

	secureBackend := len(caCert) > 0

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		// In some systems (like Windows) system cert pool is
		// not supported or no certificates are present on the
		// system - so we create a new cert pool.
		rootCAs = x509.NewCertPool()
	}

	// Add the global public crts as part of global root CAs
	for _, publicCrt := range caCerts {
		rootCAs.AddCert(publicCrt)
	}

	transport := newInternodeHTTPTransport(&tls.Config{
		RootCAs:    rootCAs,
		NextProtos: []string{"h2", "http/1.1"},
		// TLS hardening
		MinVersion:               tls.VersionTLS12,
		CipherSuites:             secureCipherSuites,
		CurvePreferences:         secureCurves,
		PreferServerCipherSuites: true,
	}, rest.DefaultTimeout)()

	r := mux.NewRouter()
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		accessKey, err := getReqAccessKey(r, "") // TODO support region
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}

		// Verify if access key exists
		tenantHost, ok := globalTenantAccessMap.Get(accessKey)
		if !ok {
			http.Error(w, fmt.Sprintf("access key '%s' does not exist", accessKey), http.StatusBadRequest)
			return
		}

		director := func(r *http.Request) {
			r.Header.Add("X-Forwarded-Host", r.Host)
			r.Header.Add("X-Real-IP", r.RemoteAddr)

			if secureBackend {
				r.URL.Scheme = "https"
			} else {
				r.URL.Scheme = "http"
			}

			r.URL.Host = tenantHost
		}

		proxy := &httputil.ReverseProxy{
			Director:  director,
			Transport: transport,
		}

		proxy.ServeHTTP(w, r)
	})

	loggedRouter := handlers.CombinedLoggingHandler(os.Stdout, r)
	s := &http.Server{
		Handler:        loggedRouter,
		Addr:           ":8443",
		MaxHeaderBytes: 1 << 20,
		TLSConfig: &tls.Config{
			// TLS hardening
			PreferServerCipherSuites: true,
			MinVersion:               tls.VersionTLS12,
			NextProtos:               []string{"h2", "http/1.1"},
			Certificates:             certs,
			CipherSuites:             secureCipherSuites,
			CurvePreferences:         secureCurves,
		},
	}

	log.Fatalln(s.ListenAndServeTLS("", ""))
}
