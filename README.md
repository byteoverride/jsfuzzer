# jsfuzzer — JS Analysis Tool for Bug Bounty

Fast, concurrent CLI tool written in Go that performs deep analysis of JavaScript files for bug bounty hunting.

## What It Finds

| Category | Examples |
|---|---|
| **Secrets & Keys** | AWS, GCP, Azure, Stripe, Slack, GitHub, GitLab, Discord, Telegram, JWTs, private keys, DB connection strings, 50+ patterns |
| **DOM Sinks (XSS)** | innerHTML, eval, document.write, Function(), setTimeout(string), dangerouslySetInnerHTML, jQuery .html(), location assignment |
| **DOM Sources** | location.hash, location.search, document.referrer, window.name, URLSearchParams, postMessage listeners |
| **Endpoints** | Relative paths, full URLs, fetch/axios targets, GraphQL, WebSocket endpoints |
| **Subdomains** | All domains/subdomains referenced in JS, prioritized by target relevance |
| **Cloud** | S3 buckets, GCS, Azure Blob, Firebase, CloudFront |
| **Source Maps** | sourceMappingURL detection — exposed source maps leak original source code |
| **Frameworks** | React, Angular, Vue, jQuery, Next.js, Nuxt, Webpack, Ember, Backbone |
| **PII** | Emails, IPv4, IPv6 |
| **Interesting** | Admin/debug paths, TODO/FIXME comments, debug flags, disabled security checks |

## Installation

```bash
go install github.com/byteoverride/jsfuzzer@latest
```

## Usage

```bash
# Single URL
jsfuzzer -u https://target.com/static/app.js

# List of URLs
jsfuzzer -l jsurls.txt

# Piped input (works with tools like getJS, katana, etc.)
cat jsurls.txt | jsfuzzer

# With base URL to resolve relative endpoints
jsfuzzer -u https://target.com/js/main.js -base https://target.com

# JSON output for piping to jq
jsfuzzer -l jsurls.txt -json | jq '.[] | .secrets'

# Route through Burp proxy
jsfuzzer -u https://target.com/app.js -proxy http://127.0.0.1:8080

# Show only high+ severity findings with context
jsfuzzer -u https://target.com/app.js -severity high -ctx

# Custom headers (auth required JS)
jsfuzzer -u https://target.com/app.js -headers "Authorization:Bearer TOKEN,Cookie:session=abc"

# Custom regex
jsfuzzer -u https://target.com/app.js -r '/api/v[0-9]+/[a-z]+'

# Save to file (colors stripped automatically)
jsfuzzer -l jsurls.txt -o results.txt

# Fast scan with high concurrency
jsfuzzer -l jsurls.txt -c 20 -t 10
```

## Flags

| Flag | Default | Description |
|---|---|---|
| `-u` | | Single JS URL to scan |
| `-l` | | File containing list of JS URLs |
| `-o` | | Output file (plain text, colors stripped) |
| `-r` | | Custom regex pattern |
| `-json` | false | Output as JSON |
| `-ctx` | false | Show surrounding code context for each match |
| `-severity` | info | Minimum severity filter: critical, high, medium, low, info |
| `-base` | | Base URL to resolve relative endpoints |
| `-headers` | | Custom HTTP headers: `Key1:Val1,Key2:Val2` |
| `-proxy` | | HTTP proxy URL (e.g., `http://127.0.0.1:8080`) |
| `-c` | 10 | Max concurrent requests |
| `-t` | 15 | HTTP timeout in seconds |
| `-retries` | 2 | Number of retries on failure |
| `-v` | false | Verbose: show errors, retries, HTTP status |
| `-nocolor` | false | Disable colored output |
| `-version` | | Print version and exit |

## Severity Levels

Findings are scored by severity:

- **CRITICAL** — Exposed secrets (AWS keys, private keys, DB strings, live Stripe keys)
- **HIGH** — API keys, JWTs, bearer tokens, DOM sinks (innerHTML, eval), source maps
- **MEDIUM** — Generic secrets, disabled security flags, dynamic fetch/XHR patterns
- **LOW** — Publishable keys, emails, IPs, debug paths, interesting strings
- **INFO** — Endpoints, subdomains, framework detection

Use `-severity high` to hide low-priority noise and focus on actionable findings.

## Pipeline Examples

```bash
# Recon pipeline: find JS files, then analyze them
echo target.com | katana -jc | grep '\.js$' | jsfuzzer -ctx

# Extract just endpoints for further fuzzing
jsfuzzer -l jsurls.txt -json | jq -r '.[].endpoints[].match' | sort -u

# Extract secrets only
jsfuzzer -l jsurls.txt -json | jq '.[].secrets'

# Feed endpoints to ffuf
jsfuzzer -u https://target.com/app.js -json | jq -r '.[].endpoints[].match' | ffuf -u https://target.com/FUZZ -w -

# Find DOM XSS sinks
jsfuzzer -l jsurls.txt -json | jq '.[].sinks[] | select(.severity == "CRITICAL")'
```
