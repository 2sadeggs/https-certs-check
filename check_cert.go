package main

import (
	"bufio"
	"crypto/tls"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// checkCertExpiry retrieves the certificate from the provided URL and checks if it's expiring within n days.
func checkCertExpiry(url string, timeout time.Duration, daysUntilExpiry int) error {
	// Create an HTTP client with a custom transport and timeout
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, // We don't need to verify the server's certificate
			},
		},
		Timeout: timeout, // Set a timeout for the HTTP client
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

	// Calculate days remaining until expiry
	now := time.Now().UTC()
	expiry := cert.NotAfter.UTC()
	daysRemaining := int(expiry.Sub(now).Hours() / 24)

	// Check if the certificate is expiring within n days
	if daysRemaining <= daysUntilExpiry && daysRemaining >= 0 {
		fmt.Printf("Certificate for %s is expiring in %d days: valid from %s to %s\n", url, daysRemaining, cert.NotBefore, cert.NotAfter)
	}

	return nil
}

// readURLsFromFile reads URLs from a file, one per line, and removes duplicates.
func readURLsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %v", err)
	}
	defer file.Close()

	var urls []string
	urlSet := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		url := strings.TrimSpace(scanner.Text())
		if url != "" && !strings.HasPrefix(url, "#") { // Skip empty lines and lines starting with '#'
			if _, exists := urlSet[url]; !exists {
				urls = append(urls, url)
				urlSet[url] = struct{}{}
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading file: %v", err)
	}
	return urls, nil
}

// worker function to check certificates concurrently
func worker(urls <-chan string, timeout time.Duration, daysUntilExpiry int, wg *sync.WaitGroup) {
	defer wg.Done()
	for url := range urls {
		fmt.Printf("Checking certificate for %s...\n", url)
		if err := checkCertExpiry(url, timeout, daysUntilExpiry); err != nil {
			fmt.Fprintf(os.Stderr, "Error checking certificate for %s: %v\n", url, err)
		}
	}
}

func main() {
	// Define command-line flags
	fileFlag := flag.String("file", "uris.txt", "Path to the file containing the list of URLs (default: uris.txt)")
	workersFlag := flag.Int("workers", 10, "Number of concurrent workers (default: 10)")
	timeoutFlag := flag.Int("timeout", 3, "HTTP request timeout in seconds (default: 3)")
	daysFlag := flag.Int("days", 30, "Number of days within which the certificate will expire (default: 30)")
	flag.Parse()

	// Convert timeoutFlag to time.Duration
	timeout := time.Duration(*timeoutFlag) * time.Second

	// Read URLs from the file
	urls, err := readURLsFromFile(*fileFlag)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading URLs from file: %v\n", err)
		os.Exit(1)
	}

	// Create a channel to send URLs to workers
	urlChan := make(chan string)

	// Use a wait group to wait for all workers to finish
	var wg sync.WaitGroup

	// Start a number of workers
	numWorkers := *workersFlag // Number of concurrent workers
	for i := 0; i < numWorkers; i++ {
		wg.Add(1)
		go worker(urlChan, timeout, *daysFlag, &wg)
	}

	// Send URLs to the workers
	for _, url := range urls {
		urlChan <- url
	}

	// Close the channel and wait for all workers to finish
	close(urlChan)
	wg.Wait()
}
