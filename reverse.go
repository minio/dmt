package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"time"

	xhttp "github.com/minio/minio/cmd/http"
	"github.com/minio/minio/cmd/rest"
	"golang.org/x/net/http2"
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
			return nil, fmt.Errorf("Could not read PEM block from file %s", certFile)
		}

		var x509Cert *x509.Certificate
		if x509Cert, err = x509.ParseCertificate(pemBlock.Bytes); err != nil {
			return nil, err
		}

		x509Certs = append(x509Certs, x509Cert)
	}

	if len(x509Certs) == 0 {
		return nil, fmt.Errorf("Empty public certificate file %s", certFile)
	}

	return x509Certs, nil
}

var (
	caCert  string
	tlsCert string
	tlsKey  string
	backend string

	globalDNSCache *xhttp.DNSCache
)

func init() {
	flag.StringVar(&caCert, "ca-cert", "/etc/nginx/ssl/ca.crt", "CA certificates")
	flag.StringVar(&tlsCert, "tls-cert", "/etc/nginx/ssl/tls.crt", "TLS certificate")
	flag.StringVar(&tlsKey, "tls-key", "/etc/nginx/ssl/tls.key", "TLS key")
	flag.StringVar(&backend, "backend", "https://minio:9001", "MinIO backend")
	globalDNSCache = xhttp.NewDNSCache(3*time.Second, 10*time.Second)
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

func main() {
	flag.Parse()

	defer globalDNSCache.Stop()

	certs, err := ParsePublicCertFile(caCert)
	if err != nil {
		log.Fatal(err)
	}

	origin, err := url.Parse(backend)
	if err != nil {
		log.Fatal(err)
	}

	rootCAs, _ := x509.SystemCertPool()
	if rootCAs == nil {
		// In some systems (like Windows) system cert pool is
		// not supported or no certificates are present on the
		// system - so we create a new cert pool.
		rootCAs = x509.NewCertPool()
	}

	// Add the global public crts as part of global root CAs
	for _, publicCrt := range certs {
		rootCAs.AddCert(publicCrt)
	}

	transport := newInternodeHTTPTransport(&tls.Config{
		RootCAs: rootCAs,
	}, rest.DefaultTimeout)()

	director := func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Add("X-Forwarded-Proto", origin.Scheme)
		req.Header.Add("X-Real-IP", req.RemoteAddr)
		req.URL.Scheme = origin.Scheme
		req.URL.Host = origin.Host
	}

	proxy := &httputil.ReverseProxy{
		Director:  director,
		Transport: transport,
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	log.Fatal(http.ListenAndServeTLS(":8443", tlsCert, tlsKey, nil))
}
