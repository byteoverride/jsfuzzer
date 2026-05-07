package main

import (
	"net/url"
	"regexp"
	"strings"
	"sync"
)

// Finding represents a single match with context
type Finding struct {
	Pattern  string   `json:"pattern"`
	Match    string   `json:"match"`
	Category Category `json:"-"`
	CatName  string   `json:"category"`
	Severity Severity `json:"-"`
	SevName  string   `json:"severity"`
	Context  string   `json:"context,omitempty"`
}

// ScanResult holds all findings for a single JS file
type ScanResult struct {
	URL          string    `json:"url"`
	Secrets      []Finding `json:"secrets,omitempty"`
	Sinks        []Finding `json:"sinks,omitempty"`
	Sources      []Finding `json:"sources,omitempty"`
	Endpoints    []Finding `json:"endpoints,omitempty"`
	Subdomains   []Finding `json:"subdomains,omitempty"`
	Cloud        []Finding `json:"cloud,omitempty"`
	PII          []Finding `json:"pii,omitempty"`
	Frameworks   []Finding `json:"frameworks,omitempty"`
	SourceMaps   []Finding `json:"sourcemaps,omitempty"`
	Interesting  []Finding `json:"interesting,omitempty"`
	Error        string    `json:"error,omitempty"`
}

// TotalFindings returns the count of all findings
func (r *ScanResult) TotalFindings() int {
	return len(r.Secrets) + len(r.Sinks) + len(r.Sources) + len(r.Endpoints) +
		len(r.Subdomains) + len(r.Cloud) + len(r.PII) + len(r.Frameworks) +
		len(r.SourceMaps) + len(r.Interesting)
}

// HasHighSeverity returns true if any critical/high finding exists
func (r *ScanResult) HasHighSeverity() bool {
	for _, f := range r.Secrets {
		if f.Severity <= SevHigh {
			return true
		}
	}
	for _, f := range r.Sinks {
		if f.Severity <= SevHigh {
			return true
		}
	}
	for _, f := range r.Sources {
		if f.Severity <= SevHigh {
			return true
		}
	}
	for _, f := range r.SourceMaps {
		if f.Severity <= SevHigh {
			return true
		}
	}
	return false
}

// compiled regex cache
var (
	compiledPatterns     []compiledPattern
	compiledPatternsOnce sync.Once
)

type compiledPattern struct {
	Pattern
	re *regexp.Regexp
}

func getCompiledPatterns() []compiledPattern {
	compiledPatternsOnce.Do(func() {
		for _, p := range AllPatterns() {
			re, err := regexp.Compile(p.Regex)
			if err != nil {
				continue
			}
			compiledPatterns = append(compiledPatterns, compiledPattern{Pattern: p, re: re})
		}
	})
	return compiledPatterns
}

// contextWindow controls how many characters of surrounding context to capture
const contextWindow = 80

// extractContext returns surrounding context for a match position
func extractContext(content string, matchStart, matchEnd int) string {
	start := matchStart - contextWindow
	if start < 0 {
		start = 0
	}
	end := matchEnd + contextWindow
	if end > len(content) {
		end = len(content)
	}
	ctx := content[start:end]
	// Clean up for display: replace newlines, collapse whitespace
	ctx = strings.ReplaceAll(ctx, "\n", " ")
	ctx = strings.ReplaceAll(ctx, "\r", "")
	ctx = strings.ReplaceAll(ctx, "\t", " ")
	return strings.TrimSpace(ctx)
}

// Extract runs all patterns against content and returns categorized results
func Extract(content, base, sourceURL, customRegex string, showContext bool) ScanResult {
	seen := make(map[string]struct{})
	result := ScanResult{URL: sourceURL}

	// Custom regex mode — only run the user's regex
	if customRegex != "" {
		re, err := regexp.Compile(customRegex)
		if err != nil {
			result.Error = "invalid custom regex: " + err.Error()
			return result
		}
		for _, loc := range re.FindAllStringIndex(content, -1) {
			match := content[loc[0]:loc[1]]
			if _, exists := seen[match]; exists {
				continue
			}
			seen[match] = struct{}{}
			f := Finding{
				Pattern:  "custom",
				Match:    match,
				Category: CatEndpoint,
				CatName:  CatEndpoint.String(),
				Severity: SevInfo,
				SevName:  SevInfo.String(),
			}
			if showContext {
				f.Context = extractContext(content, loc[0], loc[1])
			}
			result.Endpoints = append(result.Endpoints, f)
		}
		return result
	}

	// Run all compiled patterns
	for _, cp := range getCompiledPatterns() {
		locs := cp.re.FindAllStringSubmatchIndex(content, -1)
		for _, loc := range locs {
			// Use first capture group if available, else full match
			matchStart, matchEnd := loc[0], loc[1]
			if len(loc) >= 4 && loc[2] >= 0 {
				matchStart, matchEnd = loc[2], loc[3]
			}
			match := content[matchStart:matchEnd]

			// Clean quotes
			match = strings.Trim(match, "\"'`")
			if len(match) < 4 {
				continue
			}

			// Dedup
			dedup := cp.Name + ":" + match
			if _, ok := seen[dedup]; ok {
				continue
			}
			seen[dedup] = struct{}{}

			f := Finding{
				Pattern:  cp.Name,
				Match:    match,
				Category: cp.Category,
				CatName:  cp.Category.String(),
				Severity: cp.Severity,
				SevName:  cp.Severity.String(),
			}
			if showContext {
				f.Context = extractContext(content, loc[0], loc[1])
			}

			// Resolve endpoints against base
			if cp.Category == CatEndpoint {
				if isFilteredEndpoint(match) {
					continue
				}
				f.Match = resolveURL(match, base)
			}

			// Categorize into result
			switch cp.Category {
			case CatSecret:
				result.Secrets = append(result.Secrets, f)
			case CatSink:
				result.Sinks = append(result.Sinks, f)
			case CatSource:
				result.Sources = append(result.Sources, f)
			case CatEndpoint:
				result.Endpoints = append(result.Endpoints, f)
			case CatCloud:
				result.Cloud = append(result.Cloud, f)
			case CatPII:
				result.PII = append(result.PII, f)
			case CatFramework:
				result.Frameworks = append(result.Frameworks, f)
			case CatSourceMap:
				result.SourceMaps = append(result.SourceMaps, f)
			case CatInteresting:
				result.Interesting = append(result.Interesting, f)
			}
		}
	}

	// Extract subdomains from content
	extractSubdomains(content, sourceURL, &result, seen)

	return result
}

// isFilteredEndpoint returns true for common false positive endpoints
func isFilteredEndpoint(path string) bool {
	if strings.ContainsAny(path, " {}[]()<>;") {
		return true
	}
	// Filter common JS/CSS noise
	noise := []string{".js.map", ".css.map", ".woff", ".ttf", ".eot", ".png", ".jpg", ".gif", ".svg", ".ico"}
	lower := strings.ToLower(path)
	for _, n := range noise {
		if strings.HasSuffix(lower, n) {
			return true
		}
	}
	return false
}

// resolveURL prepends base URL to relative paths
func resolveURL(path, base string) string {
	if base == "" || strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") || strings.HasPrefix(path, "ws://") || strings.HasPrefix(path, "wss://") {
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

// extractSubdomains finds subdomains referenced in JS content
func extractSubdomains(content, sourceURL string, result *ScanResult, seen map[string]struct{}) {
	// Get the base domain from source URL to find related subdomains
	var baseDomain string
	if parsed, err := url.Parse(sourceURL); err == nil && parsed.Host != "" {
		parts := strings.Split(parsed.Hostname(), ".")
		if len(parts) >= 2 {
			baseDomain = parts[len(parts)-2] + "." + parts[len(parts)-1]
		}
	}

	// Find FQDN-like strings — require at least 2 labels before TLD, each label 2+ chars
	re := regexp.MustCompile(`(?:https?://)?([a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9](?:\.[a-zA-Z0-9][a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])*\.(?:com|net|org|io|co|dev|app|us|uk|de|fr|cn|ru|in|br|au|ca|nl|se|no|fi|dk|ch|at|be|es|it|pt|pl|cz|sk|hu|ro|bg|hr|rs|ua|lt|lv|ee|za|ng|ke|eg|il|ae|sa|jp|kr|tw|hk|sg|my|th|ph|id|vn|nz|mx|ar|cl|pe|gov|edu|mil|int|info|biz|name|pro|museum|coop|aero|xyz|online|site|tech|cloud|ai|me|tv|cc|ly|to|fm|am|gg|gl|sh|ws))\b`)
	for _, match := range re.FindAllStringSubmatch(content, -1) {
		domain := strings.ToLower(match[1])

		// Skip if it doesn't look like a real domain
		if !isLikelyDomain(domain) {
			continue
		}
		// Skip common CDN/library domains unless they match target
		if isCommonDomain(domain) && (baseDomain == "" || !strings.HasSuffix(domain, baseDomain)) {
			continue
		}

		dedup := "subdomain:" + domain
		if _, ok := seen[dedup]; ok {
			continue
		}
		seen[dedup] = struct{}{}

		sev := SevInfo
		// Higher severity if it matches the target's base domain
		if baseDomain != "" && strings.HasSuffix(domain, baseDomain) {
			sev = SevLow
		}

		result.Subdomains = append(result.Subdomains, Finding{
			Pattern:  "subdomain",
			Match:    domain,
			Category: CatSubdomain,
			CatName:  CatSubdomain.String(),
			Severity: sev,
			SevName:  sev.String(),
		})
	}
}

// isLikelyDomain checks if the string looks like a real domain (not minified JS)
func isLikelyDomain(domain string) bool {
	parts := strings.Split(domain, ".")
	// Require at least a subdomain + domain + TLD (3 parts) OR 2 parts with meaningful labels
	if len(parts) < 2 {
		return false
	}
	// Reject very short domains (e.g., "ke.th")
	if len(domain) < 6 {
		return false
	}
	// Reject if any label is a common JS keyword/method
	jsNoise := map[string]bool{
		"this": true, "self": true, "window": true, "document": true,
		"prototype": true, "constructor": true, "length": true, "name": true,
		"type": true, "data": true, "value": true, "target": true,
		"parent": true, "child": true, "node": true, "text": true,
		"call": true, "apply": true, "bind": true, "push": true,
		"slice": true, "concat": true, "join": true, "split": true,
		"test": true, "exec": true, "match": true, "replace": true,
		"trim": true, "keys": true, "each": true, "find": true,
		"filter": true, "index": true, "first": true, "last": true,
		"prev": true, "next": true, "body": true, "head": true,
		"style": true, "class": true, "event": true, "error": true,
		"state": true, "props": true, "cache": true, "queue": true,
	}
	for _, p := range parts[:len(parts)-1] { // Check all labels except TLD
		if jsNoise[strings.ToLower(p)] {
			return false
		}
		// Reject single-char labels (minified variable names)
		if len(p) < 2 {
			return false
		}
	}
	return true
}

func isCommonDomain(domain string) bool {
	common := []string{
		"googleapis.com", "gstatic.com", "google.com", "facebook.com",
		"fbcdn.net", "cloudflare.com", "cdnjs.cloudflare.com",
		"jsdelivr.net", "unpkg.com", "bootstrapcdn.com",
		"jquery.com", "w3.org", "schema.org", "mozilla.org",
		"apple.com", "microsoft.com", "github.com", "npmjs.com",
		"gravatar.com", "wordpress.com", "wp.com",
	}
	for _, c := range common {
		if domain == c || strings.HasSuffix(domain, "."+c) {
			return true
		}
	}
	return false
}
