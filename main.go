package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"
)

var version = "3.0.0"

func main() {
	// Flags — short and long forms
	urlFlag := flag.String("u", "", "Single JS URL to scan")
	listFlag := flag.String("l", "", "File containing list of JS URLs")
	outputFlag := flag.String("o", "", "Output file (plain text, colors stripped)")
	regexFlag := flag.String("r", "", "Custom regex pattern")
	headersFlag := flag.String("headers", "", "Custom headers: 'Key1:Val1,Key2:Val2'")
	baseFlag := flag.String("base", "", "Base URL to resolve relative endpoints")
	proxyFlag := flag.String("proxy", "", "HTTP proxy (e.g., http://127.0.0.1:8080)")
	concFlag := flag.Int("c", 10, "Max concurrent requests")
	timeoutFlag := flag.Int("t", 15, "HTTP timeout in seconds")
	retriesFlag := flag.Int("retries", 2, "Number of retries on failure")
	jsonFlag := flag.Bool("json", false, "Output as JSON")
	contextFlag := flag.Bool("ctx", false, "Show surrounding code context for matches")
	verboseFlag := flag.Bool("v", false, "Verbose: show errors and retries")
	noColorArg := flag.Bool("nocolor", false, "Disable colored output")
	sevFlag := flag.String("severity", "info", "Minimum severity to show: critical, high, medium, low, info")
	versionFlag := flag.Bool("version", false, "Print version and exit")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "%s\n", color("jsfuzzer v"+version+" — JS Analysis for Bug Bounty", Bold+Cyan))
		fmt.Fprintf(os.Stderr, "%s\n\n", color("Extracts secrets, sinks, sources, endpoints, subdomains from JS files", Dim))
		fmt.Fprintf(os.Stderr, "Usage:\n")
		fmt.Fprintf(os.Stderr, "  jsfuzzer -u <url>              Scan single JS URL\n")
		fmt.Fprintf(os.Stderr, "  jsfuzzer -l <file>             Scan list of JS URLs\n")
		fmt.Fprintf(os.Stderr, "  cat urls.txt | jsfuzzer        Scan from stdin\n")
		fmt.Fprintf(os.Stderr, "\nFlags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	if *versionFlag {
		fmt.Println("jsfuzzer v" + version)
		os.Exit(0)
	}

	// Set global color state
	noColor = *noColorArg

	// Set log writer for verbose output
	logWriter = os.Stderr

	// Parse minimum severity
	minSev := parseSeverity(*sevFlag)

	// Collect URLs
	var urls []string
	if *urlFlag != "" {
		urls = append(urls, *urlFlag)
	} else if *listFlag != "" {
		file, err := os.Open(*listFlag)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s %v\n", color("[ERR]", Red), err)
			os.Exit(1)
		}
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			if u := strings.TrimSpace(scanner.Text()); u != "" && !strings.HasPrefix(u, "#") {
				urls = append(urls, u)
			}
		}
		file.Close()
	} else {
		stat, _ := os.Stdin.Stat()
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			scanner := bufio.NewScanner(os.Stdin)
			for scanner.Scan() {
				if u := strings.TrimSpace(scanner.Text()); u != "" && !strings.HasPrefix(u, "#") {
					urls = append(urls, u)
				}
			}
		}
	}

	if len(urls) == 0 {
		fmt.Fprintf(os.Stderr, "%s No URLs provided. Use -u, -l, or pipe via stdin.\n", color("[ERR]", Red))
		flag.Usage()
		os.Exit(1)
	}

	// Build fetch config
	cfg := FetchConfig{
		Headers:     ParseHeaders(*headersFlag),
		Proxy:       *proxyFlag,
		Timeout:     time.Duration(*timeoutFlag) * time.Second,
		Retries:     *retriesFlag,
		Concurrency: *concFlag,
		Verbose:     *verboseFlag,
		UserAgent:   "Mozilla/5.0 (compatible; jsfuzzer/" + version + ")",
	}

	if !*jsonFlag {
		fmt.Fprintf(os.Stderr, "%s Scanning %s URL(s) [concurrency=%d, timeout=%ds]\n",
			color("[*]", Bold+Blue), color(fmt.Sprintf("%d", len(urls)), Bold+White), *concFlag, *timeoutFlag)
		if *proxyFlag != "" {
			fmt.Fprintf(os.Stderr, "%s Proxy: %s\n", color("[*]", Bold+Blue), *proxyFlag)
		}
	}

	// Run scans
	results := RunScans(urls, cfg, *baseFlag, *regexFlag, *contextFlag)

	// Collect and output results
	var allResults []ScanResult
	var fileBuffer strings.Builder

	for r := range results {
		allResults = append(allResults, r)
		if !*jsonFlag {
			formatted := FormatPretty(r, *contextFlag, minSev)
			fmt.Print(formatted)
			if *outputFlag != "" {
				fileBuffer.WriteString(StripANSI(formatted))
			}
		}
	}

	// JSON output
	if *jsonFlag {
		jsonStr, err := FormatJSON(allResults)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s JSON error: %v\n", color("[ERR]", Red), err)
			os.Exit(1)
		}
		fmt.Println(jsonStr)
		if *outputFlag != "" {
			fileBuffer.WriteString(jsonStr)
		}
	} else {
		// Print summary
		summary := FormatSummary(allResults)
		fmt.Print(summary)
		if *outputFlag != "" {
			fileBuffer.WriteString(StripANSI(summary))
		}
	}

	// Write to file
	if *outputFlag != "" {
		err := os.WriteFile(*outputFlag, []byte(fileBuffer.String()), 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s writing file: %v\n", color("[ERR]", Red), err)
		} else if !*jsonFlag {
			fmt.Fprintf(os.Stderr, "%s Results saved to %s\n", color("[+]", Green), *outputFlag)
		}
	}
}

func parseSeverity(s string) Severity {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return SevCritical
	case "high":
		return SevHigh
	case "medium", "med":
		return SevMedium
	case "low":
		return SevLow
	default:
		return SevInfo
	}
}
