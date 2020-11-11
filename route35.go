package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"os"
	"strings"
	"time"

	xhttp "github.com/minio/minio/cmd/http"
	"github.com/minio/minio/cmd/rest"
	"github.com/minio/minio/pkg/auth"
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
	caCert    string
	tlsCert   string
	tlsKey    string
	routeFile string

	globalDNSCache *xhttp.DNSCache
)

func init() {
	flag.StringVar(&tlsKey, "tls-key", "/etc/route35/tls.key", "TLS key")
	flag.StringVar(&tlsCert, "tls-cert", "/etc/route35/tls.crt", "TLS certificate")
	flag.StringVar(&caCert, "ca-cert", "/etc/route35/ca.crt", "CA certificates")
	flag.StringVar(&routeFile, "routes", "/etc/route35/routes.json", "default access routes file")
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

var tenantAccessMapping = map[string]string{}

// isValidRegion - verify if incoming region value is valid with configured Region.
func isValidRegion(reqRegion string, confRegion string) bool {
	if confRegion == "" {
		return true
	}
	if confRegion == "US" {
		confRegion = ""
	}
	// Some older s3 clients set region as "US" instead of
	// globalMinioDefaultRegion, handle it.
	if reqRegion == "US" {
		reqRegion = ""
	}
	return reqRegion == confRegion
}

// parse credentialHeader string into its structured form.
func parseCredentialHeader(credElement string, region string) (accessKey string, err error) {
	creds := strings.SplitN(strings.TrimSpace(credElement), "=", 2)
	if len(creds) != 2 {
		return "", errors.New("error missing fields")
	}
	if creds[0] != "Credential" {
		return "", errors.New("missing Credential tag")
	}
	credElements := strings.Split(strings.TrimSpace(creds[1]), "/")
	if len(credElements) < 5 {
		return "", errors.New("malformed Credential tag")
	}
	accessKey = strings.Join(credElements[:len(credElements)-4], "/") // The access key may contain one or more `/`
	if !auth.IsAccessKeyValid(accessKey) {
		return "", errors.New("invalid access key id")
	}

	credElements = credElements[len(credElements)-4:]
	if _, err = time.Parse(yyyymmdd, credElements[0]); err != nil {
		return accessKey, fmt.Errorf("invalid credential date %s", err)
	}

	// Region is set to be empty, we use whatever was sent by the
	// request and proceed further. This is a work-around to address
	// an important problem for ListBuckets() getting signed with
	// different regions.
	if region == "" {
		region = credElements[1]
	}

	// Should validate region, only if region is set.
	if !isValidRegion(credElements[1], region) {
		return accessKey, errors.New("invalid region")

	}
	switch serviceType(credElements[2]) {
	case serviceSTS:
	case serviceS3:
	default:
		return accessKey, fmt.Errorf("invalid service type %s", credElements[2])
	}
	if credElements[3] != "aws4_request" {
		return accessKey, errors.New("invalid AWS signature version")
	}
	return accessKey, nil
}

type serviceType string

const (
	serviceS3  serviceType = "s3"
	serviceSTS serviceType = "sts"
)

// AWS Signature Version '4' constants.
const (
	signV4Algorithm = "AWS4-HMAC-SHA256"
	iso8601Format   = "20060102T150405Z"
	yyyymmdd        = "20060102"
)

func getReqAccessKey(r *http.Request, region string) (string, error) {
	accessKey, err := parseCredentialHeader("Credential="+r.URL.Query().Get(xhttp.AmzCredential), region)
	if err != nil {
		// Strip off the Algorithm prefix.
		v4Auth := strings.TrimPrefix(r.Header.Get("Authorization"), signV4Algorithm)
		authFields := strings.Split(strings.TrimSpace(v4Auth), ",")
		if len(authFields) != 3 {
			return accessKey, errors.New("missing expected fields")
		}
		accessKey, err = parseCredentialHeader(authFields[0], region)
	}
	return accessKey, err
}

func main() {
	flag.Parse()

	defer globalDNSCache.Stop()

	r, err := os.Open(routeFile)
	if err != nil {
		log.Fatal(err)
	}

	d := json.NewDecoder(r)
	if err = d.Decode(&tenantAccessMapping); err != nil {
		log.Fatal(err)
	}

	r.Close()

	certs, err := ParsePublicCertFile(caCert)
	if err != nil {
		log.Fatal(err)
	}

	secureBackend := len(caCert) > 0

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

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		accessKey, err := getReqAccessKey(r, "") // TODO support region
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
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

			tenantHost, ok := tenantAccessMapping[accessKey]
			if !ok {
				http.Error(w, fmt.Sprintf("no tenant found for accessKey %s", accessKey), http.StatusBadRequest)
				return
			}

			r.URL.Host = tenantHost
		}

		proxy := &httputil.ReverseProxy{
			Director:  director,
			Transport: transport,
		}

		proxy.ServeHTTP(w, r)
	})

	log.Fatal(http.ListenAndServeTLS(":8443", tlsCert, tlsKey, nil))
}
