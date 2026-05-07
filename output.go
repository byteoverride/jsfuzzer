package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// ANSI color codes
const (
	Reset     = "\033[0m"
	Bold      = "\033[1m"
	Dim       = "\033[2m"
	Red       = "\033[31m"
	Green     = "\033[32m"
	Yellow    = "\033[33m"
	Blue      = "\033[34m"
	Purple    = "\033[35m"
	Cyan      = "\033[36m"
	White     = "\033[37m"
	BgRed     = "\033[41m"
	BgYellow  = "\033[43m"
)

var noColor bool

func color(text, c string) string {
	if noColor {
		return text
	}
	return c + text + Reset
}

func sevColor(s Severity) string {
	switch s {
	case SevCritical:
		return Bold + Red
	case SevHigh:
		return Red
	case SevMedium:
		return Yellow
	case SevLow:
		return Blue
	default:
		return Dim
	}
}

func sevTag(s Severity) string {
	tag := fmt.Sprintf("[%s]", s.String())
	return color(tag, sevColor(s))
}

// FormatPretty renders a ScanResult as colored terminal output
func FormatPretty(r ScanResult, showContext bool, minSeverity Severity) string {
	var b bytes.Buffer

	// Header
	divider := strings.Repeat("─", 70)
	b.WriteString(color(divider, Dim) + "\n")
	b.WriteString(color("  TARGET: ", Bold+White) + color(r.URL, Bold+Cyan) + "\n")
	b.WriteString(color(divider, Dim) + "\n")

	if r.Error != "" {
		b.WriteString(color("  [ERR] "+r.Error, Red) + "\n")
		return b.String()
	}

	if r.TotalFindings() == 0 {
		b.WriteString(color("  No findings.\n", Dim))
		return b.String()
	}

	// Secrets
	if filtered := filterSev(r.Secrets, minSeverity); len(filtered) > 0 {
		b.WriteString(color("\n  ⚠ SECRETS & KEYS", Bold+Red) + color(fmt.Sprintf(" (%d)", len(filtered)), Dim) + "\n")
		printFindings(&b, filtered, showContext)
	}

	// Sinks
	if filtered := filterSev(r.Sinks, minSeverity); len(filtered) > 0 {
		b.WriteString(color("\n  ◉ DOM SINKS (XSS)", Bold+Yellow) + color(fmt.Sprintf(" (%d)", len(filtered)), Dim) + "\n")
		printFindings(&b, filtered, showContext)
	}

	// Sources
	if filtered := filterSev(r.Sources, minSeverity); len(filtered) > 0 {
		b.WriteString(color("\n  ◎ DOM SOURCES", Bold+Yellow) + color(fmt.Sprintf(" (%d)", len(filtered)), Dim) + "\n")
		printFindings(&b, filtered, showContext)
	}

	// Source Maps
	if filtered := filterSev(r.SourceMaps, minSeverity); len(filtered) > 0 {
		b.WriteString(color("\n  ⊕ SOURCE MAPS", Bold+Purple) + color(fmt.Sprintf(" (%d)", len(filtered)), Dim) + "\n")
		printFindings(&b, filtered, showContext)
	}

	// Cloud
	if filtered := filterSev(r.Cloud, minSeverity); len(filtered) > 0 {
		b.WriteString(color("\n  ☁ CLOUD INFRASTRUCTURE", Bold+Cyan) + color(fmt.Sprintf(" (%d)", len(filtered)), Dim) + "\n")
		printFindings(&b, filtered, showContext)
	}

	// Endpoints
	if filtered := filterSev(r.Endpoints, minSeverity); len(filtered) > 0 {
		sort.Slice(filtered, func(i, j int) bool { return filtered[i].Match < filtered[j].Match })
		b.WriteString(color("\n  → ENDPOINTS", Bold+Green) + color(fmt.Sprintf(" (%d)", len(filtered)), Dim) + "\n")
		printFindings(&b, filtered, showContext)
	}

	// Subdomains
	if filtered := filterSev(r.Subdomains, minSeverity); len(filtered) > 0 {
		sort.Slice(filtered, func(i, j int) bool { return filtered[i].Match < filtered[j].Match })
		b.WriteString(color("\n  ⊞ SUBDOMAINS", Bold+Blue) + color(fmt.Sprintf(" (%d)", len(filtered)), Dim) + "\n")
		printFindings(&b, filtered, showContext)
	}

	// PII
	if filtered := filterSev(r.PII, minSeverity); len(filtered) > 0 {
		b.WriteString(color("\n  ⊙ PII & NETWORK", Bold+Cyan) + color(fmt.Sprintf(" (%d)", len(filtered)), Dim) + "\n")
		printFindings(&b, filtered, showContext)
	}

	// Frameworks
	if filtered := filterSev(r.Frameworks, minSeverity); len(filtered) > 0 {
		// Deduplicate framework names
		seen := make(map[string]bool)
		var unique []Finding
		for _, f := range filtered {
			if !seen[f.Pattern] {
				seen[f.Pattern] = true
				unique = append(unique, f)
			}
		}
		b.WriteString(color("\n  ⊡ FRAMEWORKS", Bold+White) + color(fmt.Sprintf(" (%d)", len(unique)), Dim) + "\n")
		for _, f := range unique {
			b.WriteString(fmt.Sprintf("    %s %s\n", sevTag(f.Severity), color(f.Pattern, White)))
		}
	}

	// Interesting
	if filtered := filterSev(r.Interesting, minSeverity); len(filtered) > 0 {
		b.WriteString(color("\n  ✦ INTERESTING", Bold+Purple) + color(fmt.Sprintf(" (%d)", len(filtered)), Dim) + "\n")
		printFindings(&b, filtered, showContext)
	}

	b.WriteString("\n")
	return b.String()
}

func printFindings(b *bytes.Buffer, findings []Finding, showContext bool) {
	for _, f := range findings {
		label := color(f.Pattern, sevColor(f.Severity))
		b.WriteString(fmt.Sprintf("    %s %s  %s\n", sevTag(f.Severity), label, truncate(f.Match, 120)))
		if showContext && f.Context != "" {
			b.WriteString(fmt.Sprintf("           %s\n", color(truncate(f.Context, 160), Dim)))
		}
	}
}

func filterSev(findings []Finding, min Severity) []Finding {
	var out []Finding
	for _, f := range findings {
		if f.Severity <= min {
			out = append(out, f)
		}
	}
	return out
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}

// FormatJSON returns JSON output for all results
func FormatJSON(results []ScanResult) (string, error) {
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// FormatSummary returns a one-line summary of all scans
func FormatSummary(results []ScanResult) string {
	var totalSecrets, totalSinks, totalSources, totalEndpoints, totalSubdomains, totalCloud, totalPII, totalMaps, totalInteresting, totalErrors int
	for _, r := range results {
		totalSecrets += len(r.Secrets)
		totalSinks += len(r.Sinks)
		totalSources += len(r.Sources)
		totalEndpoints += len(r.Endpoints)
		totalSubdomains += len(r.Subdomains)
		totalCloud += len(r.Cloud)
		totalPII += len(r.PII)
		totalMaps += len(r.SourceMaps)
		totalInteresting += len(r.Interesting)
		if r.Error != "" {
			totalErrors++
		}
	}

	var b bytes.Buffer
	divider := strings.Repeat("═", 70)
	b.WriteString(color(divider, Bold+White) + "\n")
	b.WriteString(color("  SCAN SUMMARY", Bold+White) + "\n")
	b.WriteString(color(divider, Bold+White) + "\n")
	b.WriteString(fmt.Sprintf("  URLs Scanned:  %s\n", color(fmt.Sprintf("%d", len(results)), Bold+White)))
	if totalErrors > 0 {
		b.WriteString(fmt.Sprintf("  Errors:        %s\n", color(fmt.Sprintf("%d", totalErrors), Red)))
	}
	b.WriteString(fmt.Sprintf("  Secrets:       %s\n", countColor(totalSecrets, Red)))
	b.WriteString(fmt.Sprintf("  Sinks:         %s\n", countColor(totalSinks, Yellow)))
	b.WriteString(fmt.Sprintf("  Sources:       %s\n", countColor(totalSources, Yellow)))
	b.WriteString(fmt.Sprintf("  Source Maps:   %s\n", countColor(totalMaps, Purple)))
	b.WriteString(fmt.Sprintf("  Cloud:         %s\n", countColor(totalCloud, Cyan)))
	b.WriteString(fmt.Sprintf("  Endpoints:     %s\n", countColor(totalEndpoints, Green)))
	b.WriteString(fmt.Sprintf("  Subdomains:    %s\n", countColor(totalSubdomains, Blue)))
	b.WriteString(fmt.Sprintf("  PII:           %s\n", countColor(totalPII, Cyan)))
	b.WriteString(fmt.Sprintf("  Interesting:   %s\n", countColor(totalInteresting, Purple)))
	b.WriteString(color(divider, Bold+White) + "\n")
	return b.String()
}

func countColor(n int, c string) string {
	s := fmt.Sprintf("%d", n)
	if n > 0 {
		return color(s, Bold+c)
	}
	return color(s, Dim)
}

// StripANSI removes ANSI escape codes for file output
func StripANSI(str string) string {
	re := regexp.MustCompile(`\x1b\[[0-9;]*m`)
	return re.ReplaceAllString(str, "")
}
