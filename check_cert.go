package main

import (
	"bufio"
	"crypto/tls"
	"flag"
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

	fmt.Printf("Certificate for %s is valid: valid from %s to %s\n", url, cert.NotBefore, cert.NotAfter)
	return nil
}

// readURLsFromFile reads URLs from a file, one per line.
func readURLsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	var urls []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := scanner.Text()
		if url != "" {
			urls = append(urls, url) // Correct usage of append
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}
	return urls, nil
}

func main() {
	// Define command-line flags
	fileFlag := flag.String("file", "", "Path to the file containing the list of URLs")
	flag.Parse()

	// Validate flags
	if *fileFlag == "" {
		fmt.Println("Usage: check_cert -file <path_to_file>")
		os.Exit(1)
	}

	// Read URLs from the file
	urls, err := readURLsFromFile(*fileFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading URLs from file: %v\n", err)
		os.Exit(1)
	}

	// Check each URL's certificate
	for _, url := range urls {
		fmt.Printf("Checking certificate for %s...\n", url)
		if err := checkCertExpiry(url); err != nil {
			fmt.Fprintf(os.Stderr, "Error checking certificate for %s: %v\n", url, err)
		}
	}
}
