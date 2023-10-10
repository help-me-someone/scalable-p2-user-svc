package main

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
)

var proxy map[string]string

func init() {
	proxy = make(map[string]string)
	proxy["upload"] = "7000"
}

// This is where the reverse proxy routing logic resides.
// Yes, it's bad to hardcore but who is going to stop me?
// We expect service apis to be something like: "/svc/<service_name>/*"
func Target(path string) (string, error) {
	// Remove the front / and then split the url by separating '/'s
	parts := strings.Split(strings.TrimPrefix(path, "/"), "/")
	if len(parts) <= 1 {
		return "", fmt.Errorf("failed to parse target host from path: %s", path)
	}

	if parts[0] != "svc" {
		return "", fmt.Errorf("failed to parse target host from path: %s", path)
	}

	targetHost := "localhost"
	targetPort, ok := proxy[parts[1]]
	if !ok {
		return "", fmt.Errorf("failed to parse target host from path: %s", path)
	}

	targetAddr := fmt.Sprintf(
		"http://%s:%s/%s",
		targetHost, targetPort, strings.Join(parts[2:], "/"),
	)

	return targetAddr, nil
}

// What is even going on. God knows.
func Proxy(address *url.URL) *httputil.ReverseProxy {
	p := httputil.NewSingleHostReverseProxy(address)
	p.Director = func(request *http.Request) {
		request.Host = address.Host
		request.URL.Scheme = address.Scheme
		request.URL.Host = address.Host
		request.URL.Path = address.Path
	}
	return p
}
