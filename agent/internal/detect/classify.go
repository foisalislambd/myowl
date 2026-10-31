// Package detect contains the intrusion / anomaly detectors.
package detect

import (
	"regexp"
	"strings"

	"github.com/myowl/myowl/agent/internal/logs"
	"github.com/myowl/myowl/agent/internal/model"
)

// Request flag names.
const (
	FlagSQLi      = "sqli"
	FlagXSS       = "xss"
	FlagTraversal = "traversal"
	FlagRCE       = "rce"
	FlagScanner   = "scanner_path"
	FlagBadBot    = "bad_bot"
	FlagBadMethod = "bad_method"
)

var (
	sqliRe  = regexp.MustCompile(`union(\s|/\*.*?\*/|\+)+(all(\s|\+)+)?select|'\s*(or|and)\s+'?\w*'?\s*=\s*'?\w*|\bor\s+1\s*=\s*1\b|sleep\s*\(\s*\d+\s*\)|benchmark\s*\(|information_schema|waitfor\s+delay|extractvalue\s*\(|updatexml\s*\(|load_file\s*\(|into\s+outfile|;\s*drop\s+table|'\s*;\s*--|"\s*or\s*"\w*"\s*=\s*"|\bpg_sleep\s*\(|@@version|0x[0-9a-f]{16,}`)
	xssRe   = regexp.MustCompile(`<\s*script|javascript\s*:|\bon(error|load|mouseover|focus|click)\s*=|<\s*(img|svg|iframe|body|object|embed)[^>]*>|alert\s*\(|document\.cookie|<\s*/\s*script|prompt\s*\(|eval\s*\(`)
	travRe  = regexp.MustCompile(`\.\./|\.\.\\|/etc/(passwd|shadow|hosts|group)|/proc/self/|c:\\windows|win\.ini|boot\.ini|file://|php://(filter|input)|/etc/issue`)
	rceRe   = regexp.MustCompile(`\$\{jndi:|;\s*(wget|curl|cat|bash|sh|nc|chmod|rm)\s|\|\s*(wget|curl|bash|sh)\b|\$\(\s*(wget|curl|id|whoami|cat)|` + "`" + `(id|whoami|uname)` + "`" + `|/bin/(ba)?sh|cmd\.exe|powershell|shell_exec|base64_decode\(|system\(|passthru\(|eval-stdin\.php|allow_url_include|auto_prepend_file|\bnohup\b`)
	badUARe = regexp.MustCompile(`(?i)sqlmap|nikto|nmap|masscan|zgrab|nuclei|dirbuster|gobuster|ffuf|wpscan|acunetix|nessus|openvas|w3af|havij|hydra|fimap|commix|jaeles|xray|feroxbuster|libwww-perl|zmeu|morfeus|netsparker|censysinspect|expanse`)
)

var scannerPaths = []string{
	"/wp-login.php", "/wp-admin", "/xmlrpc.php", "/wp-config", "/wp-content/plugins/", "/wp-includes/",
	"/.env", "/.git/", "/.git", "/.svn/", "/.hg/", "/.ds_store", "/.aws/", "/.ssh/", "/.htaccess", "/.htpasswd",
	"/phpmyadmin", "/pma/", "/myadmin", "/mysqladmin", "/dbadmin", "/adminer", "/phpinfo", "/info.php",
	"/config.php", "/configuration.php", "/admin.php", "/setup.php", "/install.php", "/shell.php", "/cmd.php",
	"/actuator", "/server-status", "/server-info", "/cgi-bin/", "/vendor/phpunit", "/boaform", "/hnap1",
	"/backup.zip", "/backup.sql", "/db.sql", "/dump.sql", "/database.sql", "/site.zip", "/www.zip",
	"/solr/admin", "/owa/", "/ecp/", "/autodiscover", "/telescope", "/_ignition", "/console", "/manager/html",
	"/druid/", "/jenkins", "/.vscode", "/.idea", "/config.json", "/docker-compose.yml", "/.dockerenv",
	"/sftp-config.json", "/id_rsa", "/geoserver", "/remote/login", "/cgi-bin/luci", "/vpn/", "/sdk",
	"/containers/json", "/api/v1/pods", "/.well-known/security.txt.bak", "/xampp", "/webdav",
}

var badMethods = map[string]bool{"CONNECT": true, "TRACE": true, "TRACK": true, "PROPFIND": true, "DEBUG": true}

// ClassifyRequest returns the threat flags for a request.
func ClassifyRequest(r *model.HTTPRequest) []string {
	var flags []string
	target := logs.DecodedTarget(r)
	if sqliRe.MatchString(target) {
		flags = append(flags, FlagSQLi)
	}
	if xssRe.MatchString(target) {
		flags = append(flags, FlagXSS)
	}
	if travRe.MatchString(target) {
		flags = append(flags, FlagTraversal)
	}
	ua := strings.ToLower(r.UA)
	if rceRe.MatchString(target) || strings.Contains(ua, "${jndi:") || strings.Contains(ua, "() {") {
		flags = append(flags, FlagRCE)
	}
	path := strings.ToLower(r.Path)
	for _, p := range scannerPaths {
		if strings.HasPrefix(path, p) || (len(p) > 6 && strings.Contains(path, p)) {
			flags = append(flags, FlagScanner)
			break
		}
	}
	if badUARe.MatchString(r.UA) {
		flags = append(flags, FlagBadBot)
	}
	if badMethods[strings.ToUpper(r.Method)] || (r.Method == "-" && r.Status == 400) {
		flags = append(flags, FlagBadMethod)
	}
	return flags
}

// FlagInfo describes a request flag in plain language.
type FlagInfo struct {
	Title    string
	Severity string
	Explain  string
	Advice   string
}

// Flags maps flag -> description.
var Flags = map[string]FlagInfo{
	FlagSQLi: {"SQL injection attempt", model.SevHigh,
		"sent %d request(s) that look like SQL injection — an attempt to trick your database into leaking or deleting data",
		"Make sure your application uses parameterised queries. If the server answered with 200 OK, check that page. Consider blocking this IP."},
	FlagXSS: {"Cross-site scripting (XSS) attempt", model.SevMedium,
		"sent %d request(s) containing hidden JavaScript — an attempt to inject code that runs in your visitors' browsers",
		"Make sure user input is escaped before it is shown on a page. Blocking the IP is usually safe."},
	FlagTraversal: {"Path traversal attempt", model.SevHigh,
		"sent %d request(s) trying to read files outside your website folder (like /etc/passwd)",
		"Check that your web server does not serve files outside the site root. Blocking this IP is recommended."},
	FlagRCE: {"Remote command execution attempt", model.SevCritical,
		"sent %d request(s) trying to make your server run commands (for example to download malware)",
		"These are serious. Keep your software updated and block this IP. If any such request got a 200 response, investigate immediately."},
	FlagScanner: {"Vulnerability scanning", model.SevLow,
		"probed %d well-known sensitive paths (like /.env, /wp-login.php or /phpmyadmin) looking for weaknesses",
		"This is very common internet background noise. Make sure none of these files exist publicly. Block the IP if it continues."},
	FlagBadBot: {"Hacking tool detected", model.SevMedium,
		"used an automated hacking tool (identified by its user agent) for %d request(s)",
		"Automated scanners look for known weaknesses. Blocking the IP is recommended."},
	FlagBadMethod: {"Unusual HTTP method", model.SevLow,
		"sent %d request(s) with unusual or malformed HTTP methods, typical of proxies abuse or scanners",
		"Usually harmless if your server rejects them, but worth blocking if repeated."},
}
