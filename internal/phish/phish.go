// Package phish mengimplementasikan heuristik penilaian risiko URL phishing
// yang berjalan 100% offline (tanpa jaringan).
package phish

import (
	"net"
	"net/url"
	"regexp"
	"strconv"
	"strings"
)

// Signal adalah satu temuan risiko beserta bobotnya.
type Signal struct {
	ID     string `json:"id"`
	Desc   string `json:"description"`
	Weight int    `json:"weight"`
}

// Level adalah klasifikasi hasil akhir.
const (
	LevelLow        = "LOW"
	LevelSuspicious = "SUSPICIOUS"
	LevelDangerous  = "DANGEROUS"
	LevelCritical   = "CRITICAL"
)

// Result adalah hasil penilaian sebuah URL.
type Result struct {
	URL     string   `json:"url"`
	Host    string   `json:"host"`
	Domain  string   `json:"registrable_domain"`
	Score   int      `json:"score"`
	Level   string   `json:"level"`
	Signals []Signal `json:"signals"`
}

// multiPartSuffixes adalah suffix TLD dua bagian yang umum
// (registrable domain = 3 label terakhir untuk suffix ini).
var multiPartSuffixes = map[string]bool{
	"co.uk": true, "org.uk": true, "ac.uk": true, "gov.uk": true,
	"co.id": true, "or.id": true, "ac.id": true, "sch.id": true, "web.id": true,
	"net.id": true, "go.id": true, "my.id": true, "biz.id": true,
	"com.au": true, "net.au": true, "org.au": true,
	"co.jp": true, "or.jp": true, "ne.jp": true, "ac.jp": true,
	"co.in": true, "net.in": true, "org.in": true, "ac.in": true, "gov.in": true,
	"com.br": true, "com.mx": true, "com.ar": true, "com.tr": true,
	"com.cn": true, "com.tw": true, "com.hk": true, "com.sg": true,
	"com.my": true, "co.th": true, "co.nz": true, "co.za": true,
	"com.ng": true, "com.eg": true, "com.sa": true, "com.pk": true,
	"com.ph": true, "com.vn": true,
}

var riskyTLDs = map[string]bool{
	"tk": true, "ml": true, "ga": true, "cf": true, "gq": true,
	"xyz": true, "top": true, "buzz": true, "click": true, "country": true,
	"work": true, "loan": true, "men": true, "mom": true, "party": true,
	"review": true, "stream": true, "gdn": true, "icu": true, "cam": true,
	"rest": true, "cyou": true, "sbs": true, "zip": true, "mov": true,
	"monster": true, "quest": true,
}

var shorteners = map[string]bool{
	"bit.ly": true, "tinyurl.com": true, "t.co": true, "goo.gl": true,
	"is.gd": true, "cutt.ly": true, "rb.gy": true, "shorturl.at": true,
	"ow.ly": true, "buff.ly": true, "rebrand.ly": true, "s.id": true,
	"bit.do": true, "soo.gd": true, "shorte.st": true, "lnkd.in": true,
}

// brands adalah daftar merek yang sering jadi sasaranny typosquatting.
var brands = []string{
	"paypal", "google", "facebook", "instagram", "whatsapp", "youtube",
	"netflix", "amazon", "apple", "microsoft", "outlook", "linkedin",
	"twitter", "stripe", "coinbase", "binance", "metamask", "steam",
	"discord", "dropbox", "dhl", "fedex", "usps", "uber", "airbnb",
	"spotify", "tiktok", "roblox",
	// merek Indonesia
	"bca", "mandiri", "bri", "bni", "cimb", "ovo", "dana", "gopay",
	"gojek", "tokopedia", "shopee", "bukalapak", "lazada", "linkaja",
	"jenius", "seabank", "jago",
}

var pathKeywords = []string{
	"login", "signin", "sign-in", "sign_in", "logon", "verify", "verification",
	"validate", "secure", "security", "account", "update", "confirm", "bank",
	"banking", "invoice", "payment", "wallet", "unlock", "recover", "suspended",
	"limited", "kyc", "otp", "credential", "webscr", "authorize", "retail",
}

var (
	pctEncodedRE = regexp.MustCompile(`%[0-9A-Fa-f]{2}`)
	credParamRE  = regexp.MustCompile(`(?i)(?:password|passwd|pwd|email|username|user|login)=`)
	leetMap      = map[rune]rune{
		'0': 'o', '1': 'l', '3': 'e', '4': 'a', '5': 's',
		'7': 't', '@': 'a', '$': 's', '!': 'i',
	}
)

// Check menilai satu URL dan mengembalikan hasil + daftar sinyal.
func Check(raw string) (Result, error) {
	u, err := normalize(raw)
	if err != nil {
		return Result{}, err
	}
	host := strings.ToLower(u.Hostname())
	res := Result{URL: u.String(), Host: host, Signals: []Signal{}}

	domain, sld, tld, labels := splitDomain(host)
	res.Domain = domain

	add := func(id, desc string, w int) {
		res.Signals = append(res.Signals, Signal{ID: id, Desc: desc, Weight: w})
	}

	// --- identitas host ---
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsPrivate() || ip.IsLoopback() {
			add("private-ip", "Host is a private/loopback IP (internal target)", 5)
		} else {
			add("ip-host", "Host is a raw IP address, not a domain", 35)
		}
	} else if isNumericHost(host) {
		add("numeric-host", "Host is a decimal/hex number (obfuscated IP)", 30)
	}
	if strings.Contains(host, "xn--") {
		add("punycode", "Punycode host (xn--) — possible IDN homograph attack", 30)
	}
	if hasNonASCII(host) {
		add("non-ascii-host", "Host contains non-ASCII characters", 20)
	}

	// --- TLD & shortener ---
	if tld != "" && riskyTLDs[tld] {
		add("risky-tld", "High-risk TLD frequently used for phishing (."+tld+")", 15)
	}
	if shorteners[domain] || shorteners[host] {
		add("shortener", "URL shortener — the final destination cannot be judged from the link", 20)
	}

	// --- karakter domain ---
	if c := strings.Count(sld, "-"); c >= 3 {
		add("many-hyphens", "Many hyphens in the domain ("+strconv.Itoa(c)+")", 10)
	}
	if len(labels) >= 5 {
		add("deep-subdomain", "Deeply nested subdomains ("+strconv.Itoa(len(labels))+" labels)", 10)
	} else if len(labels) == 4 {
		add("deep-subdomain", "Nested subdomains (4 labels)", 5)
	}

	// --- skema & port ---
	ip := net.ParseIP(host)
	isLocal := (ip != nil && (ip.IsPrivate() || ip.IsLoopback())) ||
		host == "localhost" || strings.HasPrefix(host, "localhost.")
	if !isLocal && u.Scheme != "https" {
		add("http-scheme", "Scheme is not HTTPS — traffic is unencrypted", 5)
	}
	if !isLocal {
		if p := u.Port(); p != "" && p != "80" && p != "443" {
			add("nonstandard-port", "Uncommon port (:"+p+")", 10)
		}
	}
	if u.User != nil {
		add("userinfo", "URL contains credentials (user:pass@host) — classic redirect trick", 30)
	}

	// --- isi URL ---
	full := u.String()
	if len(full) > 120 {
		add("url-too-long", "Very long URL ("+strconv.Itoa(len(full))+" characters)", 8)
	}
	if n := len(pctEncodedRE.FindAllString(full, -1)); n >= 3 {
		add("excessive-encoding", "Excessive %XX encoding ("+strconv.Itoa(n)+") — may hide the real destination", 10)
	}
	q := u.RawQuery
	if credParamRE.MatchString(q) {
		add("credential-params", "Query string contains credential parameters (password/email/user)", 12)
	}
	kw := keywordsIn(u.Path + "?" + q)
	if len(kw) > 0 {
		w := 8 * len(kw)
		if w > 24 {
			w = 24
		}
		add("suspicious-keywords", "Suspicious keywords: "+strings.Join(kw, ", "), w)
	}

	// --- typosquatting / merek ---
	checkBrands(sld, host, labels, add)

	// --- total & level ---
	for _, s := range res.Signals {
		res.Score += s.Weight
	}
	if res.Score > 100 {
		res.Score = 100
	}
	res.Level = level(res.Score)
	return res, nil
}

// checkBrands menilai kemiripan domain terhadap daftar merek.
func checkBrands(sld, host string, labels []string, add func(id, desc string, w int)) {
	norm := leetFold(sld)
	for _, b := range brands {
		if norm == b {
			if sld != b {
				// leet substitution, mis. paypa1 -> paypal
				add("typosquat", "Domain resembles brand \""+b+"\" (character substitution)", 40)
			}
			continue
		}
		d := levenshtein(norm, b)
		if d == 1 && len(b) >= 5 {
			add("typosquat", "Domain is close to brand \""+b+"\" (distance "+strconv.Itoa(d)+")", 40)
			continue
		}
		if d == 2 && len(b) >= 6 {
			add("brand-similar", "Domain similar to brand \""+b+"\"", 20)
			continue
		}
		// merek sebagai token di antara tanda hubung: secure-paypal-login.com
		matched := false
		for _, tok := range strings.Split(norm, "-") {
			if tok == b && sld != b {
				add("brand-token", "Domain contains brand \""+b+"\"", 35)
				matched = true
				break
			}
		}
		if !matched && strings.Contains(norm, b) {
			add("brand-substring", "Domain contains the brand name \""+b+"\"", 15)
		}
	}
	// merek muncul di subdomain (label sebelum registrable domain)
	regParts := strings.Split(host, ".")
	regLabels := 2
	if len(regParts) >= 3 && multiPartSuffixes[strings.Join(regParts[len(regParts)-2:], ".")] {
		regLabels = 3
	}
	var subLabels []string
	if len(regParts) > regLabels {
		subLabels = regParts[:len(regParts)-regLabels]
	}
	for _, l := range subLabels {
		nl := leetFold(l)
		for _, b := range brands {
			if nl == b || (len(b) >= 5 && levenshtein(nl, b) <= 1) {
				add("brand-subdomain", "Brand \""+b+"\" appears in the subdomain — deception trick", 35)
				return
			}
		}
	}
}

func normalize(raw string) (*url.URL, error) {
	raw = strings.TrimSpace(raw)
	raw = strings.Trim(raw, "\"'<>()")
	if !strings.Contains(raw, "://") {
		raw = "http://" + raw
	}
	return url.Parse(raw)
}

// splitDomain memecah host menjadi (registrable domain, sld, tld, semua label).
func splitDomain(host string) (domain, sld, tld string, labels []string) {
	labels = strings.Split(host, ".")
	if len(labels) >= 3 && multiPartSuffixes[strings.Join(labels[len(labels)-2:], ".")] {
		return strings.Join(labels[len(labels)-3:], "."), labels[len(labels)-3], labels[len(labels)-1], labels
	}
	if len(labels) >= 2 {
		return strings.Join(labels[len(labels)-2:], "."), labels[len(labels)-2], labels[len(labels)-1], labels
	}
	return host, host, "", labels
}

func keywordsIn(s string) []string {
	low := strings.ToLower(s)
	var out []string
	for _, k := range pathKeywords {
		if strings.Contains(low, k) {
			out = append(out, k)
		}
	}
	return out
}

func leetFold(s string) string {
	b := []rune(strings.ToLower(s))
	for i, r := range b {
		if v, ok := leetMap[r]; ok {
			b[i] = v
		}
	}
	return string(b)
}

func isNumericHost(h string) bool {
	if h == "" || strings.Contains(h, ".") {
		return false
	}
	if strings.HasPrefix(h, "0x") {
		return true
	}
	for _, r := range h {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func hasNonASCII(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

func level(score int) string {
	switch {
	case score >= 70:
		return LevelCritical
	case score >= 40:
		return LevelDangerous
	case score >= 15:
		return LevelSuspicious
	}
	return LevelLow
}

// levenshtein menghitung jarak edit antara dua string.
func levenshtein(a, b string) int {
	la, lb := len(a), len(b)
	prev := make([]int, lb+1)
	curr := make([]int, lb+1)
	for j := 0; j <= lb; j++ {
		prev[j] = j
	}
	for i := 1; i <= la; i++ {
		curr[0] = i
		for j := 1; j <= lb; j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			curr[j] = minInt(prev[j]+1, curr[j-1]+1, prev[j-1]+cost)
		}
		prev, curr = curr, prev
	}
	return prev[lb]
}

func minInt(a, b, c int) int {
	if a < b {
		if a < c {
			return a
		}
		return c
	}
	if b < c {
		return b
	}
	return c
}
