package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
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
	regexFlag   = flag.String("regex", "", "Custom regex pattern to filter output (e.g. ^/admin/)")
	headersFlag = flag.String("headers", "", "Custom headers, comma-separated (e.g., Authorization:Bearer token,User-Agent:Mozilla)")
	baseFlag    = flag.String("base", "", "Base URL to prepend to relative endpoints")
)

var defaultRegex = map[string]string{
	"google_api": `AIza[0-9A-Za-z\-_]{35}`,
	"firebase": `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`,
	"google_oauth": `ya29\.[0-9A-Za-z\-_]+`,
	"aws_access_key": `A[SK]IA[0-9A-Z]{16}`,
	"bearer_token": `bearer [a-zA-Z0-9_\-\.=:_\+/]{5,100}`,
	"api_key": `api[key|_key|\s+]+[a-zA-Z0-9_\-]{5,100}`,
	"jwt": `ey[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*`,
	"ip_address": `\b(?:\d{1,3}\.){3}\d{1,3}\b`,
	"endpoint": `/[a-zA-Z0-9_?&=\-/\.]+`,
}

type ResultGroup struct {
	APIKeys     []string
	IPs         []string
	Endpoints   []string
	Interesting []string
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

func extract(content string, customRegex string, base string) ResultGroup {
	seen := make(map[string]struct{})
	result := ResultGroup{}

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
		for _, m := range matches {
			if _, ok := seen[m]; !ok {
				seen[m] = struct{}{}
				switch name {
				case "google_api", "firebase", "google_oauth", "aws_access_key", "bearer_token", "api_key", "jwt":
					result.APIKeys = append(result.APIKeys, m)
				case "ip_address":
					result.IPs = append(result.IPs, m)
				case "endpoint":
					result.Endpoints = append(result.Endpoints, prependBase(m, base))
				default:
					result.Interesting = append(result.Interesting, m)
				}
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
	parsedURL := parsedBase.ResolveReference(&url.URL{Path: path})
	return parsedURL.String()
}

func fetchAndExtract(u string, headers http.Header, customRegex string, base string, wg *sync.WaitGroup, outChan chan<- ResultGroup) {
	defer wg.Done()
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error creating request for %s: %v\n", u, err)
		return
	}
	req.Header = headers

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error fetching %s: %v\n", u, err)
		return
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Error reading body from %s: %v\n", u, err)
		return
	}

	result := extract(string(body), customRegex, base)
	outChan <- result
}

func readInputURLs() ([]string, error) {
	var urls []string
	if *urlFlag != "" {
		urls = append(urls, *urlFlag)
	} else if *listFlag != "" {
		data, err := ioutil.ReadFile(*listFlag)
		if err != nil {
			return nil, err
		}
		lines := strings.Split(string(data), "\n")
		for _, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed != "" {
				urls = append(urls, trimmed)
			}
		}
	} else {
		info, _ := os.Stdin.Stat()
		if info.Mode()&os.ModeCharDevice == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				line := strings.TrimSpace(scanner.Text())
				if line != "" {
					urls = append(urls, line)
				}
			}
		}
	}
	return urls, nil
}

func printResults(result ResultGroup) string {
	var buf bytes.Buffer

	buf.WriteString("===== API Keys =====\n")
	if len(result.APIKeys) == 0 {
		buf.WriteString("No API keys found.\n")
	} else {
		for _, key := range result.APIKeys {
			buf.WriteString(key + "\n")
		}
	}

	buf.WriteString("\n===== IPs Found =====\n")
	if len(result.IPs) == 0 {
		buf.WriteString("No IPs found.\n")
	} else {
		for _, ip := range result.IPs {
			buf.WriteString(ip + "\n")
		}
	}

	buf.WriteString("\n===== Endpoints =====\n")
	if len(result.Endpoints) == 0 {
		buf.WriteString("No endpoints found.\n")
	} else {
		for _, ep := range result.Endpoints {
			buf.WriteString(ep + "\n")
		}
	}

	buf.WriteString("\n===== Interesting Strings =====\n")
	if len(result.Interesting) == 0 {
		buf.WriteString("None found.\n")
	} else {
		for _, it := range result.Interesting {
			buf.WriteString(it + "\n")
		}
	}
	return buf.String()
}

func main() {
	flag.Usage = func() {
		fmt.Println(`Usage: jsfuzzer [options]

Options:
  -url, -u       Single JavaScript URL to scan
  -list, -l      File containing list of JS URLs
  -output, -o    Output file to write results to
  -regex, -r     Custom regex to filter output (e.g. ^/api/)
  -headers       Custom HTTP headers (comma-separated)
  -base          Base URL to prepend to relative endpoints
  -help, -h      Show this help message`)
	}
	flag.Parse()

	urls, err := readInputURLs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "[!] Failed to get input URLs: %v\n", err)
		os.Exit(1)
	}

	if len(urls) == 0 {
		fmt.Fprintln(os.Stderr, "[!] No input URLs provided")
		os.Exit(1)
	}

	headers := parseHeaders(*headersFlag)
	var wg sync.WaitGroup
	resultsChan := make(chan ResultGroup, len(urls))

	for _, u := range urls {
		wg.Add(1)
		go fetchAndExtract(u, headers, *regexFlag, *baseFlag, &wg, resultsChan)
	}

	go func() {
		wg.Wait()
		close(resultsChan)
	}()

	var buffer bytes.Buffer
	for r := range resultsChan {
		buffer.WriteString(printResults(r))
		buffer.WriteString("\n===========================\n\n")
	}

	if *outputFlag != "" {
		err := ioutil.WriteFile(*outputFlag, buffer.Bytes(), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "[!] Failed to write to output file: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Print(buffer.String())
	}
}
