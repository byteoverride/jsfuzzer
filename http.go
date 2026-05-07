package main

import (
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// FetchConfig holds HTTP client settings
type FetchConfig struct {
	Headers     http.Header
	Proxy       string
	Timeout     time.Duration
	Retries     int
	Concurrency int
	Verbose     bool
	UserAgent   string
}

// DefaultFetchConfig returns sane defaults
func DefaultFetchConfig() FetchConfig {
	return FetchConfig{
		Headers:     http.Header{},
		Timeout:     15 * time.Second,
		Retries:     2,
		Concurrency: 10,
		UserAgent:   "Mozilla/5.0 (compatible; jsfuzzer/2.0; +https://github.com/byteoverride/jsfuzzer)",
	}
}

// buildClient creates an HTTP client with the given config
func buildClient(cfg FetchConfig) (*http.Client, error) {
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		MaxIdleConns:    cfg.Concurrency,
		IdleConnTimeout: 30 * time.Second,
	}

	if cfg.Proxy != "" {
		proxyURL, err := url.Parse(cfg.Proxy)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		transport.Proxy = http.ProxyURL(proxyURL)
	}

	return &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return fmt.Errorf("too many redirects")
			}
			return nil
		},
	}, nil
}

// fetchJS fetches a JS URL and returns the body content
func fetchJS(client *http.Client, jsURL string, cfg FetchConfig) (string, error) {
	var lastErr error
	for attempt := 0; attempt <= cfg.Retries; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Duration(attempt) * 500 * time.Millisecond)
		}

		req, err := http.NewRequest("GET", jsURL, nil)
		if err != nil {
			return "", fmt.Errorf("request error: %w", err)
		}

		// Set user agent
		if cfg.Headers.Get("User-Agent") == "" {
			req.Header.Set("User-Agent", cfg.UserAgent)
		}

		// Apply custom headers
		for k, v := range cfg.Headers {
			req.Header[k] = v
		}

		resp, err := client.Do(req)
		if err != nil {
			lastErr = err
			if cfg.Verbose {
				fmt.Fprintf(logWriter, "[RETRY %d/%d] %s: %v\n", attempt+1, cfg.Retries, jsURL, err)
			}
			continue
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}

		if resp.StatusCode >= 400 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			if cfg.Verbose {
				fmt.Fprintf(logWriter, "[WARN] %s returned HTTP %d\n", jsURL, resp.StatusCode)
			}
			continue
		}

		return string(body), nil
	}
	return "", lastErr
}

// logWriter is set to os.Stderr in main
var logWriter io.Writer

// FetchAndExtract fetches a JS file and extracts findings
func FetchAndExtract(client *http.Client, jsURL string, cfg FetchConfig, base, customRegex string, showContext bool) ScanResult {
	content, err := fetchJS(client, jsURL, cfg)
	if err != nil {
		r := ScanResult{URL: jsURL, Error: err.Error()}
		if cfg.Verbose {
			fmt.Fprintf(logWriter, "[ERR] %s: %v\n", jsURL, err)
		}
		return r
	}

	// Auto-detect base from source URL if not explicitly set
	scanBase := base
	if scanBase == "" {
		scanBase = jsURL
	}

	return Extract(content, scanBase, jsURL, customRegex, showContext)
}

// RunScans processes all URLs concurrently with a semaphore
func RunScans(urls []string, cfg FetchConfig, base, customRegex string, showContext bool) <-chan ScanResult {
	results := make(chan ScanResult, len(urls))

	client, err := buildClient(cfg)
	if err != nil {
		// Return error for all URLs
		go func() {
			for _, u := range urls {
				results <- ScanResult{URL: u, Error: err.Error()}
			}
			close(results)
		}()
		return results
	}

	sem := make(chan struct{}, cfg.Concurrency)
	var wg sync.WaitGroup

	for _, u := range urls {
		wg.Add(1)
		go func(jsURL string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results <- FetchAndExtract(client, jsURL, cfg, base, customRegex, showContext)
		}(u)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	return results
}

// ParseHeaders parses "Key1:Val1,Key2:Val2" into http.Header
func ParseHeaders(headerStr string) http.Header {
	headers := http.Header{}
	if headerStr == "" {
		return headers
	}
	for _, h := range strings.Split(headerStr, ",") {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	return headers
}
