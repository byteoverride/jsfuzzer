package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
)

// ANSI Color Codes for terminal output
const (
	ColorReset  = "\033[0m"
	ColorRed    = "\033[31m"
	ColorGreen  = "\033[32m"
	ColorYellow = "\033[33m"
	ColorBlue   = "\033[34m"
	ColorPurple = "\033[35m"
	ColorCyan   = "\033[36m"
	ColorBold   = "\033[1m"
)

var (
	urlFlag     = flag.String("url", "", "Specify a single JS URL")
	listFlag    = flag.String("list", "", "Specify a file with a list of JS URLs")
	outputFlag  = flag.String("output", "", "Specify an output file (plain text)")
	regexFlag   = flag.String("regex", "", "Custom regex pattern to filter output")
	headersFlag = flag.String("headers", "", "Custom headers, comma-separated")
	baseFlag    = flag.String("base", "", "Base URL to prepend to relative endpoints")
	noColorFlag = flag.Bool("nocolor", false, "Disable colored output")
)

// Improved Regex Patterns
var defaultRegex = map[string]string{
	// Cloud & Infrastructure
	"aws_key":      `((?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16})`,
	"google_api":   `AIza[0-9A-Za-z\\-_]{35}`,
	"google_oauth": `ya29\.[0-9A-Za-z\\-_]+`,
	"firebase":     `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`,
	"heroku_api":   `[hH]eroku[0-9A-Za-z_-]+`,
	"azure_key":    `DefaultEndpointsProtocol=[a-zA-Z0-9]+;AccountName=[a-zA-Z0-9]+;AccountKey=[a-zA-Z0-9+/=]{80,};`,

	// SaaS & Payments
	"stripe_key": `(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}`,
	"slack_token": `xox[baprs]-([0-9a-zA-Z]{10,48})?`,
	"twilio_key":  `SK[0-9a-fA-F]{32}`,
	"mailgun_api": `key-[0-9a-zA-Z]{32}`,
	"paypal_b64":  `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,

	// Generic & PII
	"bearer_token": `(?i)bearer\s+[a-zA-Z0-9_\-\.\=:\_\+/]{20,100}`,
	"generic_api":  `(?i)(?:key|api|token|secret|password|auth)[=: \t"]+([a-zA-Z0-9_\-]{16,64})`,
	"jwt":          `ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`,
	"email":        `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
	"ip_address":   `\b(?:\d{1,3}\.){3}\d{1,3}\b`,

	// URLs & Endpoints (Tightened)
	"endpoint":    `(?:"|')(((?:/|\.\./|\./)[a-zA-Z0-9_?&=\-.]{2,})|((?:[a-zA-Z0-9-]+\.)+[a-zA-Z0-9-]{2,}(?:/[a-zA-Z0-9_?&=\-.]*)*))(?:"|')`,
	"s3_bucket":   `[a-z0-9.-]+\.s3\.amazonaws\.com|[a-z0-9.-]+\.s3-[a-z0-9-]\.amazonaws\.com`,
	"potential_s": `(?i)(admin|password|secret|config|auth|private)`,
}

type ResultGroup struct {
	URL         string
	Secrets     map[string][]string
	Endpoints   []string
	CloudURLs   []string
	Emails      []string
	IPs         []string
	Interesting []string
}

func extract(content, customRegex, base, sourceURL string) ResultGroup {
	seen := make(map[string]struct{})
	result := ResultGroup{
		URL:     sourceURL,
		Secrets: make(map[string][]string),
	}

	// 1. Handle Custom Regex if provided
	if customRegex != "" {
		re, err := regexp.Compile(customRegex)
		if err == nil {
			for _, match := range re.FindAllString(content, -1) {
				if _, exists := seen[match]; !exists {
					seen[match] = struct{}{}
					result.Endpoints = append(result.Endpoints, match)
				}
			}
		}
		return result
	}

	// 2. Iterate over default regex patterns
	for name, pattern := range defaultRegex {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllStringSubmatch(content, -1) // Use Submatch to catch groups

		for _, matchGroup := range matches {
			// If the regex has a capture group, take the group (index 1), else take the full match (index 0)
			match := matchGroup[0]
			if len(matchGroup) > 1 {
				match = matchGroup[1]
			}

			// Clean up quotes from endpoint matches
			match = strings.Trim(match, "\"'")

			if len(match) < 4 { // Ignore very short matches
				continue
			}
			if _, ok := seen[match]; ok {
				continue
			}
			seen[match] = struct{}{}

			switch {
			// Secrets
			case strings.Contains(name, "key"), strings.Contains(name, "token"),
				strings.Contains(name, "secret"), strings.Contains(name, "auth"),
				strings.Contains(name, "jwt"), name == "google_api", name == "firebase":
				
				result.Secrets[name] = append(result.Secrets[name], match)

			// Infrastructure
			case name == "ip_address":
				result.IPs = append(result.IPs, match)
			case name == "s3_bucket":
				result.CloudURLs = append(result.CloudURLs, match)
			
			// Navigation
			case name == "endpoint":
				// Filter out common false positives for endpoints
				if !strings.ContainsAny(match, " {}[]()<>;") && !strings.HasPrefix(match, "//") {
					fullURL := prependBase(match, base)
					result.Endpoints = append(result.Endpoints, fullURL)
				}

			// PII
			case name == "email":
				result.Emails = append(result.Emails, match) // FIXED LINE
			
			// Misc
			default:
				result.Interesting = append(result.Interesting, match)
			}
		}
	}
	return result
}

func prependBase(path, base string) string {
	if base == "" || strings.HasPrefix(path, "http") {
		return path
	}
	parsedBase, err := url.Parse(base)
	if err != nil {
		return path
	}
	ref, err := url.Parse(path)
	if err != nil {
		return path
	}
	return parsedBase.ResolveReference(ref).String()
}

func fetchAndExtract(u string, headers http.Header, customRegex, base string, wg *sync.WaitGroup, out chan<- ResultGroup) {
	defer wg.Done()
	
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error { return nil }, // Follow redirects
	}

	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return
	}
	
	// Default UA if not provided
	if headers.Get("User-Agent") == "" {
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; JScanner/1.0)")
	}
	
	for k, v := range headers {
		req.Header[k] = v
	}

	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return
	}
	
	// If base URL is not explicitly set, try to use the source URL directory
	scanBase := base
	if scanBase == "" {
		scanBase = u
	}

	out <- extract(string(body), customRegex, scanBase, u)
}

// Helper to colorize text
func colorize(text, color string) string {
	if *noColorFlag {
		return text
	}
	return color + text + ColorReset
}

func printPretty(result ResultGroup) string {
	var b bytes.Buffer
	w := tabwriter.NewWriter(&b, 0, 0, 2, ' ', 0)

	// Header
	header := fmt.Sprintf("\n%s\n SCAN RESULTS FOR: %s\n%s\n", 
		strings.Repeat("=", 60), result.URL, strings.Repeat("=", 60))
	b.WriteString(colorize(header, ColorBold+ColorBlue))

	// Secrets (High Priority)
	if len(result.Secrets) > 0 {
		b.WriteString(colorize("\n[!] CRITICAL: SECRETS & KEYS FOUND\n", ColorBold+ColorRed))
		for provider, keys := range result.Secrets {
			for _, k := range keys {
				fmt.Fprintf(w, "  %s\t: %s\n", colorize(strings.ToUpper(provider), ColorRed), k)
			}
		}
		w.Flush()
	}

	// Cloud Buckets
	if len(result.CloudURLs) > 0 {
		b.WriteString(colorize("\n[+] CLOUD INFRASTRUCTURE\n", ColorBold+ColorYellow))
		for _, v := range result.CloudURLs {
			fmt.Fprintf(w, "  %s\n", v)
		}
		w.Flush()
	}

	// Endpoints
	if len(result.Endpoints) > 0 {
		sort.Strings(result.Endpoints)
		b.WriteString(colorize(fmt.Sprintf("\n[+] ENDPOINTS FOUND (%d)\n", len(result.Endpoints)), ColorBold+ColorGreen))
		for _, v := range result.Endpoints {
			fmt.Fprintf(w, "  %s\n", v)
		}
		w.Flush()
	}

	// PII
	if len(result.Emails) > 0 || len(result.IPs) > 0 {
		b.WriteString(colorize("\n[+] PII & NETWORK INFO\n", ColorBold+ColorCyan))
		for _, v := range result.Emails {
			fmt.Fprintf(w, "  Email\t: %s\n", v)
		}
		for _, v := range result.IPs {
			fmt.Fprintf(w, "  IP\t: %s\n", v)
		}
		w.Flush()
	}

	// Interesting/Misc
	if len(result.Interesting) > 0 {
		b.WriteString(colorize("\n[+] INTERESTING STRINGS\n", ColorPurple))
		for _, v := range result.Interesting {
			fmt.Fprintf(w, "  %s\n", v)
		}
		w.Flush()
	}

	return b.String()
}

func parseHeaders(headerStr string) http.Header {
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

func main() {
	flag.Parse()

	// Handle input
	var urls []string
	if *urlFlag != "" {
		urls = append(urls, *urlFlag)
	} else if *listFlag != "" {
		file, err := os.Open(*listFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error opening list file: %v\n", err)
			os.Exit(1)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if u := strings.TrimSpace(scanner.Text()); u != "" {
				urls = append(urls, u)
			}
		}
		file.Close()
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				if u := strings.TrimSpace(scanner.Text()); u != "" {
					urls = append(urls, u)
				}
			}
		}
	}

	if len(urls) == 0 {
		fmt.Println(colorize("[!] No input URLs provided. Use -url, -list or pipe via stdin.", ColorRed))
		os.Exit(1)
	}

	// Processing
	headers := parseHeaders(*headersFlag)
	results := make(chan ResultGroup, len(urls))
	var wg sync.WaitGroup

	fmt.Printf(colorize("[*] Starting scan on %d URL(s)...\n", ColorBold+ColorBlue), len(urls))

	for _, u := range urls {
		wg.Add(1)
		go fetchAndExtract(u, headers, *regexFlag, *baseFlag, &wg, results)
	}

	go func() {
		wg.Wait()
		close(results)
	}()

	// Output Handling
	var buffer bytes.Buffer
	for res := range results {
		formatted := printPretty(res)
		
		// Print to console
		fmt.Print(formatted)
		
		// Buffer for file output (strip colors for file)
		if *outputFlag != "" {
			plain := stripANSI(formatted)
			buffer.WriteString(plain)
			buffer.WriteString("\n")
		}
	}

	if *outputFlag != "" {
		err := os.WriteFile(*outputFlag, buffer.Bytes(), 0644)
		if err != nil {
			fmt.Printf("Error writing output file: %v\n", err)
		} else {
			fmt.Printf(colorize("\n[+] Results saved to %s\n", ColorGreen), *outputFlag)
		}
	}
}

// Regex to strip ANSI codes for file output
func stripANSI(str string) string {
	ansi := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return ansi.ReplaceAllString(str, "")
}
