package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// healthURL turns a listen address into a URL reachable from the same host.
func healthURL(listen string, useTLS bool) string {
	host, port, err := net.SplitHostPort(listen)
	if err != nil {
		host, port = "", "8787"
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	scheme := "http"
	if useTLS {
		scheme = "https"
	}
	return fmt.Sprintf("%s://%s/api/auth/status", scheme, net.JoinHostPort(host, port))
}

// healthcheck returns 0 when the dashboard answers on its listen address.
func healthcheck(listen string, useTLS bool) int {
	c := &http.Client{
		Timeout: 4 * time.Second,
		// Local loopback probe of our own (possibly self-signed) certificate.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, //nolint:gosec
	}
	resp, err := c.Get(healthURL(listen, useTLS))
	if err != nil {
		fmt.Fprintln(os.Stderr, "unhealthy:", err)
		return 1
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "unhealthy: HTTP", resp.StatusCode)
		return 1
	}
	fmt.Println("ok")
	return 0
}
