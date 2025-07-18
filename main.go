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
	"strings"
	"sync"
)

var (
	urlFlag     = flag.String("url", "", "Specify a single JS URL")
	listFlag    = flag.String("list", "", "Specify a file with a list of JS URLs")
	outputFlag  = flag.String("output", "", "Specify an output file")
	regexFlag   = flag.String("regex", "", "Custom regex pattern to filter output (e.g. ^/api/)")
	headersFlag = flag.String("headers", "", "Custom headers, comma-separated (e.g., Authorization:Bearer token,User-Agent:Mozilla)")
	baseFlag    = flag.String("base", "", "Base URL to prepend to relative endpoints")
)

var defaultRegex = map[string]string{
	"google_api":     `AIza[0-9A-Za-z\-_]{35}`,
	"firebase":       `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`,
	"google_oauth":   `ya29\.[0-9A-Za-z\-_]+`,
	"aws_access_key": `A[SK]IA[0-9A-Z]{16}`,
	"bearer_token":   `bearer [a-zA-Z0-9_\-\.\=:\_\+/]{5,100}`,
	"api_key":        `(?i)(api[_\s]?key)[\s:="']{0,5}[a-z0-9_\-]{10,}`,
	"jwt":            `ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`,
	"ip_address":     `\b(?:\d{1,3}\.){3}\d{1,3}\b`,
	"endpoint":       `/[a-zA-Z0-9_?&=\-/\.]+`,
	"third_party":    `https?://[a-zA-Z0-9\-_.:]+(/[a-zA-Z0-9_?&=\-/\.]*)?`,
	"email":          `[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}`,
	"interesting":    `(?i)(POST|GET|api|setRequestHeader|\.headers|onreadystatechange|getParameter\(\)|parameter)`,
}

type ResultGroup struct {
	APIKeys           map[string][]string
	Endpoints         []string
	ThirdPartyAPIs    []string
	EmailInteractions []string
	IPs               []string
	Interesting       []string
}

func classifyAPIKey(key string) string {
	switch {
	case strings.HasPrefix(key, "sk_live_"):
		return "stripe"
	case strings.HasPrefix(key, "AIza"):
		return "google"
	case strings.HasPrefix(key, "ya29."):
		return "google_oauth"
	case strings.HasPrefix(key, "AAAA"):
		return "firebase"
	case strings.HasPrefix(key, "ASIA") || strings.HasPrefix(key, "AKIA"):
		return "aws"
	default:
		return "unknown"
	}
}

func parseHeaders(headerStr string) http.Header {
	headers := http.Header{}
	for _, h := range strings.Split(headerStr, ",") {
		parts := strings.SplitN(h, ":", 2)
		if len(parts) == 2 {
			headers.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
		}
	}
	return headers
}

func extract(content, customRegex, base string) ResultGroup {
	seen := make(map[string]struct{})
	result := ResultGroup{
		APIKeys: make(map[string][]string),
	}

	if customRegex != "" {
		re := regexp.MustCompile(customRegex)
		for _, match := range re.FindAllString(content, -1) {
			if _, exists := seen[match]; !exists {
				seen[match] = struct{}{}
				result.Endpoints = append(result.Endpoints, prependBase(match, base))
			}
		}
		return result
	}

	for name, pattern := range defaultRegex {
		re := regexp.MustCompile(pattern)
		matches := re.FindAllString(content, -1)
		for _, match := range matches {
			if _, ok := seen[match]; ok {
				continue
			}
			seen[match] = struct{}{}

			switch name {
			case "google_api", "firebase", "google_oauth", "aws_access_key", "bearer_token", "api_key", "jwt":
				provider := classifyAPIKey(match)
				result.APIKeys[provider] = append(result.APIKeys[provider], match)
			case "ip_address":
				result.IPs = append(result.IPs, match)
			case "endpoint":
				result.Endpoints = append(result.Endpoints, prependBase(match, base))
			case "third_party":
				result.ThirdPartyAPIs = append(result.ThirdPartyAPIs, match)
			case "email":
				result.EmailInteractions = append(result.EmailInteractions, match)
			default:
				result.Interesting = append(result.Interesting, match)
			}
		}
	}
	return result
}

func prependBase(path, base string) string {
	if base == "" || !strings.HasPrefix(path, "/") {
		return path
	}
	parsedBase, err := url.Parse(base)
	if err != nil {
		return path
	}
	return parsedBase.ResolveReference(&url.URL{Path: path}).String()
}

func fetchAndExtract(u string, headers http.Header, customRegex, base string, wg *sync.WaitGroup, out chan<- ResultGroup) {
	defer wg.Done()
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to create request for %s: %v\n", u, err)
		return
	}
	req.Header = headers

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to fetch %s: %v\n", u, err)
		return
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to read response from %s: %v\n", u, err)
		return
	}
	out <- extract(string(body), customRegex, base)
}

func readInput() ([]string, error) {
	var urls []string
	if *urlFlag != "" {
		urls = append(urls, *urlFlag)
	} else if *listFlag != "" {
		file, err := os.Open(*listFlag)
		if err != nil {
			return nil, err
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			url := strings.TrimSpace(scanner.Text())
			if url != "" {
				urls = append(urls, url)
			}
		}
		file.Close()
	} else {
		info, _ := os.Stdin.Stat()
		if info.Mode()&os.ModeCharDevice == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				url := strings.TrimSpace(scanner.Text())
				if url != "" {
					urls = append(urls, url)
				}
			}
		}
	}
	return urls, nil
}

func printStructured(result ResultGroup) string {
	var b bytes.Buffer

	b.WriteString("[+] API Endpoints:\n")
	for _, v := range result.Endpoints {
		b.WriteString(" - " + v + "\n")
	}

	b.WriteString("\n[+] Third-party Integrations:\n")
	for _, v := range result.ThirdPartyAPIs {
		b.WriteString(" - " + v + "\n")
	}

	b.WriteString("\n[+] Emails:\n")
	for _, v := range result.EmailInteractions {
		b.WriteString(" - " + v + "\n")
	}

	b.WriteString("\n[+] API Keys:\n")
	for provider, keys := range result.APIKeys {
		for _, k := range keys {
			b.WriteString(fmt.Sprintf(" - %s: %s\n", provider, k))
		}
	}

	b.WriteString("\n[+] IP Addresses:\n")
	for _, v := range result.IPs {
		b.WriteString(" - " + v + "\n")
	}

	b.WriteString("\n[+] Interesting Strings:\n")
	for _, v := range result.Interesting {
		b.WriteString(" - " + v + "\n")
	}

	return b.String()
}

func main() {
	flag.Parse()

	urls, err := readInput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error reading input: %v\n", err)
		os.Exit(1)
	}
	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "[!] No input URLs provided")
		os.Exit(1)
	}

	headers := parseHeaders(*headersFlag)
	results := make(chan ResultGroup, len(urls))
	var wg sync.WaitGroup
	for _, u := range urls {
		wg.Add(1)
		go fetchAndExtract(u, headers, *regexFlag, *baseFlag, &wg, results)
	}
	go func() {
		wg.Wait()
		close(results)
	}()

	var output bytes.Buffer
	for r := range results {
		output.WriteString(printStructured(r))
		output.WriteString("\n===========================\n\n")
	}

	if *outputFlag != "" {
		os.WriteFile(*outputFlag, output.Bytes(), 0644)
	} else {
		fmt.Print(output.String())
	}
}

