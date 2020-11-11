package k8s

import (
	"net"
	"strings"

	"github.com/minio/minio/pkg/env"
	"k8s.io/client-go/rest"
	certutil "k8s.io/client-go/util/cert"
)

func GetDMTDevK8sToken() string {
	return strings.TrimSpace(env.Get(DMTDevK8sSAToken, ""))
}

func GetK8sAPIServer() string {
	host, port := env.Get("KUBERNETES_SERVICE_HOST", ""), env.Get("KUBERNETES_SERVICE_PORT", "")
	apiServerAddress := "http://localhost:8001"
	if host != "" && port != "" {
		apiServerAddress = "https://" + net.JoinHostPort(host, port)
	}
	return env.Get(DMTK8sAPIServer, apiServerAddress)
}

func getK8sAPIServerTLSRootCA() string {
	return strings.TrimSpace(env.Get(DMTK8SAPIServerTLSRootCA, ""))
}

// getTLSClientConfig will return the right TLS configuration for the K8S client based on the configured TLS certificate
func getTLSClientConfig() rest.TLSClientConfig {
	var defaultRootCAFile = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
	var customRootCAFile = getK8sAPIServerTLSRootCA()
	tlsClientConfig := rest.TLSClientConfig{}
	if _, err := certutil.NewPool(defaultRootCAFile); err == nil {
		tlsClientConfig.CAFile = defaultRootCAFile
	}
	// if the user explicitly define a custom CA certificate, instead, we will use that
	if customRootCAFile != "" {
		if _, err := certutil.NewPool(customRootCAFile); err == nil {
			tlsClientConfig.CAFile = customRootCAFile
		}
	}
	return tlsClientConfig
}

var tlsClientConfig = getTLSClientConfig()

func GetK8sConfigWithToken(token string) *rest.Config {
	config := &rest.Config{
		Host:            GetK8sAPIServer(),
		TLSClientConfig: tlsClientConfig,
		APIPath:         "/",
		BearerToken:     token,
	}
	return config
}

func GetK8sConfig() (*rest.Config, error) {
	var config *rest.Config
	devToken := GetDMTDevK8sToken()
	if devToken != "" {
		//when doing local development, mount k8s api via `kubectl proxy`
		config = GetK8sConfigWithToken(devToken)
	} else {
		var err error
		config, err = rest.InClusterConfig()
		if err != nil {
			return nil, err
		}
	}
	return config, nil
}
