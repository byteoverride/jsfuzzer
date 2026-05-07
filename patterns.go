package main

// Severity levels for findings
type Severity int

const (
	SevCritical Severity = iota
	SevHigh
	SevMedium
	SevLow
	SevInfo
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "CRITICAL"
	case SevHigh:
		return "HIGH"
	case SevMedium:
		return "MEDIUM"
	case SevLow:
		return "LOW"
	default:
		return "INFO"
	}
}

// Category of a finding
type Category int

const (
	CatSecret Category = iota
	CatSink
	CatSource
	CatEndpoint
	CatSubdomain
	CatCloud
	CatPII
	CatFramework
	CatSourceMap
	CatInteresting
)

func (c Category) String() string {
	switch c {
	case CatSecret:
		return "SECRET"
	case CatSink:
		return "SINK"
	case CatSource:
		return "SOURCE"
	case CatEndpoint:
		return "ENDPOINT"
	case CatSubdomain:
		return "SUBDOMAIN"
	case CatCloud:
		return "CLOUD"
	case CatPII:
		return "PII"
	case CatFramework:
		return "FRAMEWORK"
	case CatSourceMap:
		return "SOURCEMAP"
	case CatInteresting:
		return "INTERESTING"
	default:
		return "UNKNOWN"
	}
}

// Pattern defines a single detection rule
type Pattern struct {
	Name     string
	Regex    string
	Category Category
	Severity Severity
}

// --- SECRET PATTERNS ---

var secretPatterns = []Pattern{
	// Cloud & Infrastructure
	{Name: "aws_access_key", Regex: `(?:A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}`, Category: CatSecret, Severity: SevCritical},
	{Name: "aws_secret_key", Regex: `(?i)aws[_\-\.]?secret[_\-\.]?access[_\-\.]?key[\s=:\"']+([A-Za-z0-9/+=]{40})`, Category: CatSecret, Severity: SevCritical},
	{Name: "aws_mws_key", Regex: `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, Category: CatSecret, Severity: SevCritical},
	{Name: "google_api_key", Regex: `AIza[0-9A-Za-z\-_]{35}`, Category: CatSecret, Severity: SevHigh},
	{Name: "google_oauth", Regex: `ya29\.[0-9A-Za-z\-_]+`, Category: CatSecret, Severity: SevCritical},
	{Name: "google_cloud_sa", Regex: `"type"\s*:\s*"service_account"`, Category: CatSecret, Severity: SevCritical},
	{Name: "google_oauth_id", Regex: `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`, Category: CatSecret, Severity: SevMedium},
	{Name: "firebase", Regex: `AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}`, Category: CatSecret, Severity: SevHigh},
	{Name: "azure_key", Regex: `(?i)(?:AccountKey|SharedAccessKey)\s*=\s*([A-Za-z0-9+/=]{40,})`, Category: CatSecret, Severity: SevCritical},
	{Name: "azure_conn_str", Regex: `DefaultEndpointsProtocol=https?;AccountName=[a-zA-Z0-9]+;AccountKey=[a-zA-Z0-9+/=]{80,};`, Category: CatSecret, Severity: SevCritical},
	{Name: "heroku_api", Regex: `(?i)heroku[a-z0-9_\-]*(?:key|token|api|secret)[=:\s"']+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})`, Category: CatSecret, Severity: SevHigh},
	{Name: "digitalocean_token", Regex: `dop_v1_[a-f0-9]{64}`, Category: CatSecret, Severity: SevCritical},
	{Name: "digitalocean_oauth", Regex: `doo_v1_[a-f0-9]{64}`, Category: CatSecret, Severity: SevCritical},
	{Name: "cloudflare_api", Regex: `(?i)cloudflare[_\-]?api[_\-]?(?:key|token)[\s=:\"']+([a-zA-Z0-9_\-]{37,})`, Category: CatSecret, Severity: SevHigh},

	// SaaS & Payments
	{Name: "stripe_secret", Regex: `sk_live_[0-9a-zA-Z]{24,}`, Category: CatSecret, Severity: SevCritical},
	{Name: "stripe_publishable", Regex: `pk_(?:live|test)_[0-9a-zA-Z]{24,}`, Category: CatSecret, Severity: SevLow},
	{Name: "stripe_test", Regex: `sk_test_[0-9a-zA-Z]{24,}`, Category: CatSecret, Severity: SevMedium},
	{Name: "slack_token", Regex: `xox[baprs]-[0-9a-zA-Z]{10,48}`, Category: CatSecret, Severity: SevCritical},
	{Name: "slack_webhook", Regex: `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,}/B[a-zA-Z0-9_]{8,}/[a-zA-Z0-9_]{24}`, Category: CatSecret, Severity: SevHigh},
	{Name: "twilio_sid", Regex: `AC[a-z0-9]{32}`, Category: CatSecret, Severity: SevHigh},
	{Name: "twilio_auth", Regex: `SK[0-9a-fA-F]{32}`, Category: CatSecret, Severity: SevCritical},
	{Name: "mailgun_api", Regex: `key-[0-9a-zA-Z]{32}`, Category: CatSecret, Severity: SevHigh},
	{Name: "mailchimp_api", Regex: `[0-9a-f]{32}-us[0-9]{1,2}`, Category: CatSecret, Severity: SevHigh},
	{Name: "paypal_braintree", Regex: `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`, Category: CatSecret, Severity: SevCritical},
	{Name: "square_access", Regex: `sq0atp-[0-9A-Za-z\-_]{22}`, Category: CatSecret, Severity: SevCritical},
	{Name: "square_oauth", Regex: `sq0csp-[0-9A-Za-z\-_]{43}`, Category: CatSecret, Severity: SevCritical},
	{Name: "sendgrid_api", Regex: `SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}`, Category: CatSecret, Severity: SevCritical},
	{Name: "sentry_dsn", Regex: `https://[a-f0-9]{32}@[a-z0-9\-\.]+\.ingest\.sentry\.io/[0-9]+`, Category: CatSecret, Severity: SevMedium},
	{Name: "algolia_api", Regex: `(?i)algolia[_\-]?api[_\-]?key[\s=:\"']+([a-zA-Z0-9]{32})`, Category: CatSecret, Severity: SevHigh},
	{Name: "mapbox_token", Regex: `pk\.[a-zA-Z0-9]{60,}\.[a-zA-Z0-9_\-]{20,}`, Category: CatSecret, Severity: SevMedium},
	{Name: "datadog_api", Regex: `(?i)(?:dd|datadog)[_\-]?api[_\-]?key[\s=:\"']+([a-f0-9]{32})`, Category: CatSecret, Severity: SevHigh},

	// VCS & CI/CD
	{Name: "github_token", Regex: `gh[pousr]_[A-Za-z0-9_]{36,}`, Category: CatSecret, Severity: SevCritical},
	{Name: "github_classic", Regex: `ghp_[A-Za-z0-9]{36}`, Category: CatSecret, Severity: SevCritical},
	{Name: "gitlab_token", Regex: `glpat-[0-9A-Za-z\-_]{20,}`, Category: CatSecret, Severity: SevCritical},
	{Name: "bitbucket_token", Regex: `(?i)bitbucket[_\-]?(?:token|secret|key)[\s=:\"']+([a-zA-Z0-9_\-]{20,})`, Category: CatSecret, Severity: SevHigh},
	{Name: "npm_token", Regex: `npm_[A-Za-z0-9]{36}`, Category: CatSecret, Severity: SevCritical},

	// Messaging & Social
	{Name: "discord_token", Regex: `[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}`, Category: CatSecret, Severity: SevCritical},
	{Name: "discord_webhook", Regex: `https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+`, Category: CatSecret, Severity: SevHigh},
	{Name: "telegram_bot", Regex: `[0-9]{8,10}:[A-Za-z0-9_-]{35}`, Category: CatSecret, Severity: SevHigh},
	{Name: "facebook_token", Regex: `EAA[A-Za-z0-9]+`, Category: CatSecret, Severity: SevHigh},
	{Name: "twitter_bearer", Regex: `AAAAAAAAAAAAAAAAAAA[A-Za-z0-9%]+`, Category: CatSecret, Severity: SevHigh},
	{Name: "shopify_token", Regex: `shpat_[a-fA-F0-9]{32}`, Category: CatSecret, Severity: SevCritical},
	{Name: "shopify_shared", Regex: `shpss_[a-fA-F0-9]{32}`, Category: CatSecret, Severity: SevCritical},

	// Databases & Connection Strings
	{Name: "db_connection", Regex: `(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp|mssql):\/\/[^\s"'<>{}|\\^\x60]{10,}`, Category: CatSecret, Severity: SevCritical},

	// Crypto & Auth
	{Name: "jwt", Regex: `eyJ[A-Za-z0-9-_=]+\.eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_.+/=]+`, Category: CatSecret, Severity: SevHigh},
	{Name: "bearer_token", Regex: `(?i)bearer\s+[a-zA-Z0-9_\-\.=:+/]{20,}`, Category: CatSecret, Severity: SevHigh},
	{Name: "basic_auth", Regex: `(?i)basic\s+[A-Za-z0-9+/=]{20,}`, Category: CatSecret, Severity: SevHigh},
	{Name: "private_key", Regex: `-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----`, Category: CatSecret, Severity: SevCritical},

	// Generic patterns (lower confidence)
	{Name: "generic_secret", Regex: `(?i)(?:secret|password|passwd|pwd|token|apikey|api_key|access_key|auth_token|credentials)[\s]*[=:]\s*[\"']([^\"']{8,64})[\"']`, Category: CatSecret, Severity: SevMedium},
	{Name: "hardcoded_password", Regex: `(?i)(?:password|passwd|pwd)\s*[:=]\s*[\"']([^\"'\s]{8,})[\"']`, Category: CatSecret, Severity: SevMedium},
}

// --- DOM SINK PATTERNS (XSS / Code Injection) ---

var sinkPatterns = []Pattern{
	// Critical: Direct HTML injection
	{Name: "innerHTML", Regex: `\.innerHTML\s*[=+]`, Category: CatSink, Severity: SevCritical},
	{Name: "outerHTML", Regex: `\.outerHTML\s*[=+]`, Category: CatSink, Severity: SevCritical},
	{Name: "document.write", Regex: `document\.write(?:ln)?\s*\(`, Category: CatSink, Severity: SevCritical},
	{Name: "insertAdjacentHTML", Regex: `\.insertAdjacentHTML\s*\(`, Category: CatSink, Severity: SevCritical},

	// Critical: Code execution
	{Name: "eval", Regex: `[^a-zA-Z0-9_]eval\s*\(`, Category: CatSink, Severity: SevCritical},
	{Name: "Function_constructor", Regex: `new\s+Function\s*\(`, Category: CatSink, Severity: SevCritical},
	{Name: "setTimeout_string", Regex: `setTimeout\s*\(\s*[\"'\x60]`, Category: CatSink, Severity: SevHigh},
	{Name: "setInterval_string", Regex: `setInterval\s*\(\s*[\"'\x60]`, Category: CatSink, Severity: SevHigh},

	// High: Navigation/redirect
	{Name: "location_assign", Regex: `(?:location|document\.location)\s*(?:\.href\s*=|\.assign\s*\(|\.replace\s*\()`, Category: CatSink, Severity: SevHigh},
	{Name: "window_open", Regex: `window\.open\s*\(`, Category: CatSink, Severity: SevMedium},

	// High: jQuery sinks
	{Name: "jquery_html", Regex: `\.\$?\s*\(\s*[^)]*\)\s*\.html\s*\(`, Category: CatSink, Severity: SevHigh},
	{Name: "jquery_append", Regex: `\.(?:append|prepend|after|before|wrap|replaceWith)\s*\(`, Category: CatSink, Severity: SevMedium},
	{Name: "jquery_selector", Regex: `\$\s*\(\s*[\"'\x60]\s*<`, Category: CatSink, Severity: SevHigh},

	// Medium: Other DOM manipulation
	{Name: "srcdoc", Regex: `\.srcdoc\s*=`, Category: CatSink, Severity: SevHigh},
	{Name: "iframe_src", Regex: `\.(?:src|href|action)\s*=\s*[^"';\n]*(?:location|document\.|window\.)`, Category: CatSink, Severity: SevHigh},
	{Name: "dom_parser", Regex: `new\s+DOMParser\s*\(`, Category: CatSink, Severity: SevMedium},
	{Name: "script_src", Regex: `\.(?:src|href)\s*=\s*[\"'\x60]?\s*(?:javascript:|data:)`, Category: CatSink, Severity: SevCritical},
	{Name: "dangerouslySetInnerHTML", Regex: `dangerouslySetInnerHTML`, Category: CatSink, Severity: SevCritical},

	// Medium: Fetch/XHR with dynamic URLs
	{Name: "fetch_dynamic", Regex: `fetch\s*\(\s*[^\"'\x60\s]`, Category: CatSink, Severity: SevMedium},
	{Name: "xhr_open_dynamic", Regex: `\.open\s*\(\s*[\"'](?:GET|POST|PUT|DELETE|PATCH)[\"']\s*,\s*[^\"'\x60\s]`, Category: CatSink, Severity: SevMedium},

	// postMessage
	{Name: "postMessage", Regex: `\.postMessage\s*\(`, Category: CatSink, Severity: SevMedium},
}

// --- DOM SOURCE PATTERNS (User-controllable input) ---

var sourcePatterns = []Pattern{
	{Name: "location_hash", Regex: `(?:location|document\.location)\.hash`, Category: CatSource, Severity: SevHigh},
	{Name: "location_search", Regex: `(?:location|document\.location)\.search`, Category: CatSource, Severity: SevHigh},
	{Name: "location_href_read", Regex: `(?:location|document\.location)\.href[^=\s]`, Category: CatSource, Severity: SevHigh},
	{Name: "location_pathname", Regex: `(?:location|document\.location)\.pathname`, Category: CatSource, Severity: SevMedium},
	{Name: "document_URL", Regex: `document\.URL`, Category: CatSource, Severity: SevHigh},
	{Name: "document_referrer", Regex: `document\.referrer`, Category: CatSource, Severity: SevHigh},
	{Name: "document_cookie", Regex: `document\.cookie`, Category: CatSource, Severity: SevMedium},
	{Name: "window_name", Regex: `window\.name`, Category: CatSource, Severity: SevHigh},
	{Name: "URLSearchParams", Regex: `new\s+URLSearchParams`, Category: CatSource, Severity: SevMedium},
	{Name: "onmessage", Regex: `(?:addEventListener\s*\(\s*[\"']message|\.onmessage\s*=)`, Category: CatSource, Severity: SevHigh},
	{Name: "fragment_read", Regex: `(?:location|window)\.hash\.(?:substr|substring|slice|split|replace)`, Category: CatSource, Severity: SevHigh},
}

// --- ENDPOINT PATTERNS ---

var endpointPatterns = []Pattern{
	// Relative paths: /api/v1/users, ./config, ../admin
	{Name: "relative_path", Regex: `(?:"|'|\x60)((?:/|\.\./|\./)[a-zA-Z0-9_/?&=#.\-@:%+~]{2,})(?:"|'|\x60)`, Category: CatEndpoint, Severity: SevInfo},
	// Full URLs
	{Name: "full_url", Regex: `(?:"|'|\x60)(https?://[a-zA-Z0-9\-._~:/?#\[\]@!$&'()*+,;=%]{8,})(?:"|'|\x60)`, Category: CatEndpoint, Severity: SevInfo},
	// API patterns in fetch/axios/ajax calls
	{Name: "fetch_url", Regex: `(?:fetch|axios|\.ajax|\.get|\.post|\.put|\.delete|\.patch)\s*\(\s*(?:"|'|\x60)([^"'\x60\s]{4,})(?:"|'|\x60)`, Category: CatEndpoint, Severity: SevMedium},
	// GraphQL endpoints
	{Name: "graphql", Regex: `(?:"|'|\x60)([^"'\x60]*(?:graphql|\/gql)[^"'\x60]*)(?:"|'|\x60)`, Category: CatEndpoint, Severity: SevMedium},
	// WebSocket endpoints
	{Name: "websocket", Regex: `(?:"|'|\x60)(wss?://[^"'\x60\s]+)(?:"|'|\x60)`, Category: CatEndpoint, Severity: SevMedium},
}

// --- CLOUD INFRASTRUCTURE ---

var cloudPatterns = []Pattern{
	{Name: "s3_bucket", Regex: `[a-z0-9][a-z0-9\-]{1,61}[a-z0-9]\.s3[.\-](?:us|eu|ap|sa|ca|me|af|cn)?[.\-]?[a-z\-]*\d*\.amazonaws\.com`, Category: CatCloud, Severity: SevMedium},
	{Name: "s3_path", Regex: `s3://[a-z0-9][a-z0-9.\-]{1,61}[a-z0-9](?:/[^\s"'<>]*)?`, Category: CatCloud, Severity: SevMedium},
	{Name: "gcs_bucket", Regex: `storage\.googleapis\.com/[a-z0-9][a-z0-9.\-_]{1,61}[a-z0-9]`, Category: CatCloud, Severity: SevMedium},
	{Name: "azure_blob", Regex: `[a-z0-9]{3,24}\.blob\.core\.windows\.net`, Category: CatCloud, Severity: SevMedium},
	{Name: "firebase_db", Regex: `[a-z0-9\-]+\.firebaseio\.com`, Category: CatCloud, Severity: SevMedium},
	{Name: "firebase_storage", Regex: `[a-z0-9\-]+\.appspot\.com`, Category: CatCloud, Severity: SevLow},
	{Name: "cloudfront", Regex: `[a-z0-9]+\.cloudfront\.net`, Category: CatCloud, Severity: SevLow},
}

// --- PII PATTERNS ---

var piiPatterns = []Pattern{
	{Name: "email", Regex: `[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`, Category: CatPII, Severity: SevLow},
	{Name: "ip_address", Regex: `\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b`, Category: CatPII, Severity: SevLow},
	{Name: "ipv6", Regex: `(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}`, Category: CatPII, Severity: SevLow},
}

// --- FRAMEWORK / LIBRARY DETECTION ---

var frameworkPatterns = []Pattern{
	{Name: "react", Regex: `(?:React\.(?:createElement|Component|render)|__REACT_DEVTOOLS|reactDom|react-dom)`, Category: CatFramework, Severity: SevInfo},
	{Name: "angular", Regex: `(?:ng-app|angular\.module|\@angular/core|ngOnInit|ngAfterViewInit)`, Category: CatFramework, Severity: SevInfo},
	{Name: "vue", Regex: `(?:new\s+Vue\s*\(|Vue\.component|__VUE__|createApp|vue-router)`, Category: CatFramework, Severity: SevInfo},
	{Name: "jquery", Regex: `(?:jQuery\s+v?|jquery)[./\s]?(\d+\.\d+(?:\.\d+)?)`, Category: CatFramework, Severity: SevInfo},
	{Name: "nextjs", Regex: `(?:__NEXT_DATA__|_next/static|next/router)`, Category: CatFramework, Severity: SevInfo},
	{Name: "nuxt", Regex: `(?:__NUXT__|nuxt\.js|_nuxt/)`, Category: CatFramework, Severity: SevInfo},
	{Name: "webpack", Regex: `(?:webpackJsonp|__webpack_require__|webpackChunk)`, Category: CatFramework, Severity: SevInfo},
	{Name: "ember", Regex: `(?:Ember\.Application|ember-cli|EmberENV)`, Category: CatFramework, Severity: SevInfo},
	{Name: "backbone", Regex: `(?:Backbone\.Model|Backbone\.View|Backbone\.Router)`, Category: CatFramework, Severity: SevInfo},
}

// --- SOURCEMAP DETECTION ---

var sourcemapPatterns = []Pattern{
	{Name: "sourcemap_url", Regex: `//[#@]\s*sourceMappingURL\s*=\s*(\S+)`, Category: CatSourceMap, Severity: SevHigh},
	{Name: "sourcemap_header", Regex: `X-SourceMap:\s*(\S+)`, Category: CatSourceMap, Severity: SevHigh},
}

// --- INTERESTING / SENSITIVE STRINGS ---

var interestingPatterns = []Pattern{
	{Name: "sensitive_path", Regex: `(?i)(?:"|'|\x60)((?:/|\.\./|\./)[a-zA-Z0-9_/\-]*(?:admin|dashboard|internal|debug|staging|dev-api|backup|config|setup|install|phpinfo|actuator|swagger|graphiql)[a-zA-Z0-9_/\-]*)(?:"|'|\x60)`, Category: CatInteresting, Severity: SevLow},
	{Name: "todo_fixme", Regex: `(?i)(?://|/\*)\s*(?:TODO|FIXME|HACK|XXX|BUG|TEMP)\s*:?\s*(.{10,80})`, Category: CatInteresting, Severity: SevInfo},
	{Name: "debug_flag", Regex: `(?i)(?:debug|verbose|test_mode|dev_mode)\s*[:=]\s*(?:true|1|"true"|'true')`, Category: CatInteresting, Severity: SevLow},
	{Name: "disabled_security", Regex: `(?i)(?:csrf|xss|cors|auth|security|verify|validate|sanitize)[_\-]?(?:enabled|check|protect|filter)\s*[:=]\s*(?:false|0|"false"|'false'|null)`, Category: CatInteresting, Severity: SevMedium},
	{Name: "version_info", Regex: `(?i)(?:version|ver|v)\s*[:=]\s*[\"'](\d+\.\d+(?:\.\d+)?)[\"']`, Category: CatInteresting, Severity: SevInfo},
}

// AllPatterns returns all pattern sets combined
func AllPatterns() []Pattern {
	var all []Pattern
	all = append(all, secretPatterns...)
	all = append(all, sinkPatterns...)
	all = append(all, sourcePatterns...)
	all = append(all, endpointPatterns...)
	all = append(all, cloudPatterns...)
	all = append(all, piiPatterns...)
	all = append(all, frameworkPatterns...)
	all = append(all, sourcemapPatterns...)
	all = append(all, interestingPatterns...)
	return all
}
