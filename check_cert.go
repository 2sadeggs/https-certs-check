package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"
)

// checkCertExpiry retrieves the certificate from the provided URL and checks its validity period.
func checkCertExpiry(url string) error {
	// Create an HTTP client with a custom transport
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // We don't need to verify the server's certificate
			},
		},
	}

	// Make a request to the URL
	resp, err := client.Get(url)
	if err != nil {
		return fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	// Retrieve the TLS connection state
	tlsState := resp.TLS
	if tlsState == nil {
		return fmt.Errorf("failed to retrieve TLS connection state")
	}

	// Get the server's certificate
	certs := tlsState.PeerCertificates
	if len(certs) == 0 {
		return fmt.Errorf("no certificates found")
	}

	// Use the first certificate (typically the leaf certificate)
	cert := certs[0]

	// Check the certificate's validity period
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("certificate is not yet valid: valid from %s", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("certificate has expired: valid until %s", cert.NotAfter)
	}

	fmt.Printf("Certificate is valid: valid from %s to %s\n", cert.NotBefore, cert.NotAfter)
	return nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Println("Usage: check_cert <url>")
		os.Exit(1)
	}
	url := os.Args[1]

	if err := checkCertExpiry(url); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
