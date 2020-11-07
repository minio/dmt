package main

import (
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
)

func main() {
	origin, _ := url.Parse(os.Args[1])

	director := func(req *http.Request) {
		req.Header.Add("X-Forwarded-Host", req.Host)
		req.Header.Add("X-Forwarded-Proto", origin.Scheme)
		req.Header.Add("X-Real-IP", req.RemoteAddr)
		req.URL.Scheme = origin.Scheme
		req.URL.Host = origin.Host
	}

	proxy := &httputil.ReverseProxy{Director: director}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		proxy.ServeHTTP(w, r)
	})

	log.Fatal(http.ListenAndServe(":8443", nil))
}
