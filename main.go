package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"
)

// ─────────────────────────────────────────────
//  CONFIG
// ─────────────────────────────────────────────

const (
	// WORKERS ≈ sum of all source maxConc: 2+20+2+2 = 26
	WORKERS       = 26
	ROUNDS        = 3
	JOB_BUF       = 50_000
	RESULT_BUF    = 100_000
	HTTP_TIMEOUT  = 10 * time.Second
	MAX_RETRIES   = 2
	BACKOFF_BASE  = 400 * time.Millisecond
	ERR_THRESHOLD = 4
	ERR_RESET     = 300 // 5 min before re-enabling — avoids spam re-enable/disable on cloud IPs
	CRT_CONCUR    = 2   // crt.sh rate-limits aggressively; keep it low
	STATS_EVERY   = 15 * time.Second
	FLUSH_EVERY   = 2 * time.Second
)

// ─────────────────────────────────────────────
//  ANSI / TTY
// ─────────────────────────────────────────────

const (
	aReset   = "\033[0m"
	aBold    = "\033[1m"
	aDim     = "\033[2m"
	aGray    = "\033[90m"
	aRed     = "\033[91m"
	aGreen   = "\033[92m"
	aYellow  = "\033[93m"
	aBlue    = "\033[94m"
	aMagenta = "\033[95m"
	aCyan    = "\033[96m"
	aWhite   = "\033[97m"
	aClearLn = "\033[2K\r"
)

var tty = isatty(os.Stderr)

func isatty(f *os.File) bool {
	fi, _ := f.Stat()
	return fi != nil && fi.Mode()&os.ModeCharDevice != 0
}

func c(code, s string) string {
	if !tty {
		return s
	}
	return code + s + aReset
}

// ─────────────────────────────────────────────
//  LOGGER
// ─────────────────────────────────────────────

var logMu sync.Mutex

func logLine(sym, symColor, msgColor, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	ts := c(aGray, time.Now().Format("15:04:05"))
	symbol := c(symColor, sym)
	logMu.Lock()
	// Clear the progress bar line before printing, then reprint it after.
	if tty {
		fmt.Fprint(os.Stderr, aClearLn)
	}
	fmt.Fprintf(os.Stderr, "%s %s  %s\n", ts, symbol, c(msgColor, msg))
	logMu.Unlock()
}

func logInfo(f string, a ...interface{})  { logLine("◆", aCyan, aWhite, f, a...) }
func logWarn(f string, a ...interface{})  { logLine("▲", aYellow, aYellow, f, a...) }
func logError(f string, a ...interface{}) { logLine("✖", aRed, aRed, f, a...) }
func logStats(f string, a ...interface{}) { logLine("●", aGreen, aGray, f, a...) }

// ─────────────────────────────────────────────
//  BANNER
// ─────────────────────────────────────────────

func printBanner() {
	if !tty {
		return
	}
	fmt.Fprint(os.Stderr, c(aMagenta+aBold, `
  ██████╗ ███████╗██╗   ██╗██╗██████╗
  ██╔══██╗██╔════╝██║   ██║██║██╔══██╗
  ██████╔╝█████╗  ██║   ██║██║██████╔╝
  ██╔══██╗██╔══╝  ╚██╗ ██╔╝██║██╔═══╝
  ██║  ██║███████╗ ╚████╔╝ ██║██║
  ╚═╝  ╚═╝╚══════╝  ╚═══╝  ╚═╝╚═╝
`))
	fmt.Fprintf(os.Stderr, "  %s %s  %s\n\n",
		c(aGray, "mass reverse IP lookup  ·"),
		c(aCyan, fmt.Sprintf("workers=%d", WORKERS)),
		c(aGray, "sources: robtex · webscan · urlscan · otx · certspotter"),
	)
}

// ─────────────────────────────────────────────
//  HTTP CLIENT
// ─────────────────────────────────────────────

var httpClient = &http.Client{
	Timeout: HTTP_TIMEOUT,
	Transport: &http.Transport{
		MaxIdleConns:        800,
		MaxIdleConnsPerHost: 150,
		IdleConnTimeout:     60 * time.Second,
		DialContext: (&net.Dialer{
			Timeout:   5 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		TLSHandshakeTimeout: 5 * time.Second,
	},
}

// ─────────────────────────────────────────────
//  API SOURCES
// ─────────────────────────────────────────────

type Source struct {
	name       string
	weight     int
	sem        chan struct{}
	errCount   int32
	disabledAt int64
	reqTotal   uint64
	reqSuccess uint64
	domsFound  uint64
}

func newSource(name string, weight, maxConc int) *Source {
	return &Source{name: name, weight: weight, sem: make(chan struct{}, maxConc)}
}

var sources = []*Source{
	newSource("robtex",  1,  2), // 429s after burst; keep low
	newSource("webscan", 3, 20), // most reliable on cloud IPs
	newSource("urlscan", 2,  2), // 429s when >2 concurrent
	newSource("otx",     2,  2), // AlienVault passive DNS; 429s when >2 concurrent
}

func (s *Source) isDisabled() bool {
	t := atomic.LoadInt64(&s.disabledAt)
	if t == 0 {
		return false
	}
	if time.Now().Unix()-t > ERR_RESET {
		atomic.StoreInt64(&s.disabledAt, 0)
		atomic.StoreInt32(&s.errCount, 0)
		logInfo("source %s re-enabled", s.name)
		return false
	}
	return true
}

func (s *Source) fail() {
	n := atomic.AddInt32(&s.errCount, 1)
	if int(n) == ERR_THRESHOLD {
		atomic.StoreInt64(&s.disabledAt, time.Now().Unix())
		logWarn("source %s disabled after %d consecutive errors", s.name, n)
	}
}

func (s *Source) ok() {
	atomic.StoreInt32(&s.errCount, 0)
	atomic.AddUint64(&s.reqSuccess, 1)
}

func (s *Source) addDoms(n int) {
	if n > 0 {
		atomic.AddUint64(&s.domsFound, uint64(n))
	}
}

var (
	pool    []*Source
	poolIdx uint64
)

func init() {
	for _, s := range sources {
		for i := 0; i < s.weight; i++ {
			pool = append(pool, s)
		}
	}
}

func pickSource(startIdx uint64, skip map[string]bool) *Source {
	n := uint64(len(pool))
	for i := uint64(0); i < n; i++ {
		s := pool[(startIdx+i)%n]
		if !skip[s.name] && !s.isDisabled() {
			return s
		}
	}
	return nil
}

// ─────────────────────────────────────────────
//  FETCHERS
// ─────────────────────────────────────────────

// ─────────────────────────────────────────────
//  USER-AGENT ROTATION
// ─────────────────────────────────────────────

var userAgents = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:125.0) Gecko/20100101 Firefox/125.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4_1) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Safari/605.1.15",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 Edg/124.0.0.0",
	"Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
	"Mozilla/5.0 (iPhone; CPU iPhone OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4.1 Mobile/15E148 Safari/604.1",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
}

var acceptLangs = []string{
	"en-US,en;q=0.9",
	"en-GB,en;q=0.9",
	"fr-FR,fr;q=0.9,en;q=0.8",
	"de-DE,de;q=0.9,en;q=0.8",
	"en-US,en;q=0.9,fr;q=0.8",
	"en-CA,en;q=0.9",
}

func randUA() string  { return userAgents[rand.Intn(len(userAgents))] }
func randLang() string { return acceptLangs[rand.Intn(len(acceptLangs))] }

// jitter adds a small random delay (50–250 ms) to smooth out request bursts.
func jitter() { time.Sleep(time.Duration(50+rand.Intn(200)) * time.Millisecond) }

func isHTML(body string) bool {
	t := strings.TrimSpace(body)
	if len(t) == 0 {
		return false
	}
	if t[0] == '<' {
		return true
	}
	n := 120
	if len(t) < n {
		n = len(t)
	}
	return strings.Contains(strings.ToLower(t[:n]), "<!doctype")
}

func doGETWithTimeout(u string, timeout time.Duration, maxRetries int) (string, error) {
	cl := &http.Client{Timeout: timeout, Transport: httpClient.Transport}
	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		if i > 0 {
			time.Sleep(BACKOFF_BASE * time.Duration(i*2))
		}
		req, err := http.NewRequest("GET", u, nil)
		if err != nil {
			return "", err
		}
		req.Header.Set("User-Agent", randUA())
		req.Header.Set("Accept", "text/html,application/xhtml+xml,application/json,*/*;q=0.9")
		req.Header.Set("Accept-Language", randLang())
		// Do NOT set Accept-Encoding: Go auto-adds gzip and auto-decompresses.
		// Setting it manually bypasses the auto-decompress and breaks JSON parsing.
		resp, err := cl.Do(req)
		if err != nil {
			lastErr = err
			continue
		}
		b, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
		resp.Body.Close()
		if err != nil {
			lastErr = err
			continue
		}
		switch resp.StatusCode {
		case 429, 503:
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			time.Sleep(3 * time.Second)
			continue
		}
		if resp.StatusCode >= 400 {
			lastErr = fmt.Errorf("HTTP %d", resp.StatusCode)
			continue
		}
		return string(b), nil
	}
	return "", lastErr
}

func doGET(u string) (string, error) {
	return doGETWithTimeout(u, HTTP_TIMEOUT, MAX_RETRIES)
}

func fetchRobtex(ip string) (string, error) {
	body, err := doGETWithTimeout("https://freeapi.robtex.com/pdns/reverse/"+ip, 15*time.Second, 1)
	if err != nil {
		return "", err
	}
	if isHTML(body) {
		return "", fmt.Errorf("HTML response (rate-limited?)")
	}
	return body, nil
}

func fetchWebscan(ip string) (string, error) {
	return doGET("https://api.webscan.cc/?action=query&ip=" + ip)
}

func fetchURLScan(ip string) (string, error) {
	body, err := doGETWithTimeout(
		fmt.Sprintf("https://urlscan.io/api/v1/search/?q=ip%%3A%s&size=100", ip),
		15*time.Second, 1,
	)
	if err != nil {
		return "", err
	}
	if isHTML(body) {
		return "", fmt.Errorf("HTML response (rate-limited?)")
	}
	return body, nil
}

func fetchOTX(ip string) (string, error) {
	body, err := doGETWithTimeout(
		fmt.Sprintf("https://otx.alienvault.com/api/v1/indicators/IPv4/%s/passive_dns", ip),
		15*time.Second, 1,
	)
	if err != nil {
		return "", err
	}
	if isHTML(body) {
		return "", fmt.Errorf("HTML response (blocked?)")
	}
	return body, nil
}

func query(s *Source, ip string) string {
	s.sem <- struct{}{}
	defer func() { <-s.sem }()

	jitter() // smooth out bursts to stay under per-source rate limits
	atomic.AddUint64(&s.reqTotal, 1)
	var body string
	var err error
	switch s.name {
	case "robtex":
		body, err = fetchRobtex(ip)
	case "webscan":
		body, err = fetchWebscan(ip)
	case "urlscan":
		body, err = fetchURLScan(ip)
	case "otx":
		body, err = fetchOTX(ip)
	}
	if err != nil {
		s.fail()
		logWarn("%-12s %-16s → %v", s.name, ip, err)
		return ""
	}
	s.ok()
	return body
}

// ─────────────────────────────────────────────
//  PARSING
// ─────────────────────────────────────────────

var seen sync.Map

func clean(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimSuffix(s, ".")
	s = strings.TrimPrefix(s, "*.")
	if i := strings.LastIndex(s, ":"); i != -1 {
		s = s[:i]
	}
	if len(s) < 4 || !strings.Contains(s, ".") {
		return ""
	}
	if strings.ContainsAny(s, " \t<>\"'{}[]()/@") {
		return ""
	}
	return s
}

func emit(d string, out chan<- string) bool {
	d = clean(d)
	if d == "" {
		return false
	}
	if _, loaded := seen.LoadOrStore(d, struct{}{}); !loaded {
		out <- d
		return true
	}
	return false
}

func parseRobtex(body string, out chan<- string) int {
	count := 0
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj map[string]json.RawMessage
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}
		if _, hasMsg := obj["msg"]; hasMsg {
			continue
		}
		for _, k := range []string{"rrname", "rdata"} {
			if raw, ok := obj[k]; ok {
				var v string
				if json.Unmarshal(raw, &v) == nil && emit(v, out) {
					count++
				}
			}
		}
	}
	return count
}

type crtEntry struct {
	CommonName string `json:"common_name"`
	NameValue  string `json:"name_value"`
}

func parseCRTSH(body string, out chan<- string) int {
	if isHTML(body) {
		return 0
	}
	var entries []crtEntry
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		if emit(e.CommonName, out) {
			count++
		}
		for _, line := range strings.Split(e.NameValue, "\n") {
			if emit(line, out) {
				count++
			}
		}
	}
	return count
}

func parseWebscan(body string, out chan<- string) int {
	var entries []struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		d := e.Domain
		d = strings.TrimPrefix(d, "http://")
		d = strings.TrimPrefix(d, "https://")
		d = strings.SplitN(d, "/", 2)[0]
		if emit(d, out) {
			count++
		}
	}
	return count
}

func parseURLScan(body string, out chan<- string) int {
	var result struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
				URL    string `json:"url"`
			} `json:"page"`
		} `json:"results"`
	}
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return 0
	}
	count := 0
	for _, r := range result.Results {
		if emit(r.Page.Domain, out) {
			count++
		}
		u := r.Page.URL
		u = strings.TrimPrefix(u, "http://")
		u = strings.TrimPrefix(u, "https://")
		if host := strings.SplitN(u, "/", 2)[0]; host != r.Page.Domain {
			if emit(host, out) {
				count++
			}
		}
	}
	return count
}

func parseBody(src, body string, out chan<- string) int {
	switch src {
	case "robtex":
		return parseRobtex(body, out)
	case "webscan":
		return parseWebscan(body, out)
	case "urlscan":
		return parseURLScan(body, out)
	case "otx":
		return parseOTX(body, out)
	}
	return 0
}

func parseOTX(body string, out chan<- string) int {
	var result struct {
		PassiveDNS []struct {
			Hostname   string `json:"hostname"`
			RecordType string `json:"record_type"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal([]byte(body), &result); err != nil {
		return 0
	}
	count := 0
	for _, entry := range result.PassiveDNS {
		if entry.RecordType == "A" || entry.RecordType == "AAAA" || entry.RecordType == "" {
			if emit(entry.Hostname, out) {
				count++
			}
		}
	}
	return count
}

// ─────────────────────────────────────────────
//  SUBDOMAIN ENRICHMENT  (certspotter)
// ─────────────────────────────────────────────

var (
	crtSeen sync.Map
	crtSem  = make(chan struct{}, CRT_CONCUR)
	crtWg   sync.WaitGroup
)

func enrichSubdomains(domain string, out chan<- string) {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return
	}
	apex := parts[len(parts)-2] + "." + parts[len(parts)-1]
	// Skip numeric-only or arpa apexes (IPs, PTR zones, etc.)
	if strings.HasSuffix(apex, ".arpa") || !strings.ContainsAny(apex, "abcdefghijklmnopqrstuvwxyz") {
		return
	}
	if _, loaded := crtSeen.LoadOrStore(apex, struct{}{}); loaded {
		return
	}
	select {
	case crtSem <- struct{}{}:
	default:
		return
	}
	crtWg.Add(1)
	go func() {
		defer func() {
			<-crtSem
			crtWg.Done()
		}()
		url := fmt.Sprintf("https://api.certspotter.com/v1/issuances?domain=%s&include_subdomains=true&expand=dns_names", apex)
		body, err := doGETWithTimeout(url, 20*time.Second, 1)
		if err != nil {
			logWarn("certspotter %-30s → %v", apex, err)
			return
		}
		n := parseCertspotter(body, out)
		if n > 0 {
			logInfo("certspotter %-30s → %s new domains", apex, c(aGreen, fmt.Sprintf("%d", n)))
		}
	}()
}

func parseCertspotter(body string, out chan<- string) int {
	var entries []struct {
		DNSNames []string `json:"dns_names"`
	}
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		for _, name := range e.DNSNames {
			if emit(name, out) {
				count++
			}
		}
	}
	return count
}

// ─────────────────────────────────────────────
//  STATS & PROGRESS
// ─────────────────────────────────────────────

var (
	ipsProcessed uint64
	domainsFound uint64
	totalIPs     uint64
	start        = time.Now()
)

func termWidth() int {
	type winsize struct{ Row, Col, Xpixel, Ypixel uint16 }
	ws := winsize{}
	syscall.Syscall(syscall.SYS_IOCTL, uintptr(os.Stderr.Fd()), syscall.TIOCGWINSZ, uintptr(unsafe.Pointer(&ws)))
	if ws.Col > 0 {
		return int(ws.Col)
	}
	if v := os.Getenv("COLUMNS"); v != "" {
		if n, _ := strconv.Atoi(v); n > 0 {
			return n
		}
	}
	return 120
}

// truncVis truncates s to maxVis visible characters, preserving ANSI escape codes.
func truncVis(s string, maxVis int) string {
	vis := 0
	inEsc := false
	for i, ch := range s {
		if ch == '\033' {
			inEsc = true
		} else if inEsc {
			if ch == 'm' {
				inEsc = false
			}
		} else {
			if vis >= maxVis {
				return s[:i] + aReset
			}
			vis++
		}
	}
	return s
}

func progressBar(done, total uint64, width int) string {
	if total == 0 {
		return strings.Repeat("░", width)
	}
	filled := int(done * uint64(width) / total)
	if filled > width {
		filled = width
	}
	bar := strings.Repeat("█", filled) + strings.Repeat("░", width-filled)
	return bar
}

func fmtDuration(d time.Duration) string {
	d = d.Round(time.Second)
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if h > 0 {
		return fmt.Sprintf("%dh%02dm%02ds", h, m, s)
	}
	if m > 0 {
		return fmt.Sprintf("%dm%02ds", m, s)
	}
	return fmt.Sprintf("%ds", s)
}

func fmtNum(n uint64) string {
	s := fmt.Sprintf("%d", n)
	out := ""
	for i, ch := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			out += ","
		}
		out += string(ch)
	}
	return out
}

func printProgress() {
	if !tty {
		return
	}
	ips := atomic.LoadUint64(&ipsProcessed)
	total := atomic.LoadUint64(&totalIPs)
	doms := atomic.LoadUint64(&domainsFound)
	elapsed := time.Since(start)
	rate := 0.0
	if elapsed.Seconds() > 0 {
		rate = float64(ips) / elapsed.Seconds()
	}

	pct := 0.0
	eta := ""
	if total > 0 {
		pct = float64(ips) / float64(total) * 100
		if rate > 0 && ips < total {
			remaining := time.Duration(float64(total-ips)/rate) * time.Second
			eta = "  ETA " + c(aYellow, fmtDuration(remaining))
		}
	}

	bar := c(aCyan, progressBar(ips, total, 24))
	progress := fmt.Sprintf(" %s %s/%s  [%s]  %.1f%%  %s domains  %.1f IP/s%s  %s",
		c(aMagenta+aBold, "▶"),
		c(aWhite, fmtNum(ips)),
		c(aGray, fmtNum(total)),
		bar,
		pct,
		c(aGreen, fmtNum(doms)),
		rate,
		eta,
		c(aGray, fmtDuration(elapsed)),
	)

	progress = truncVis(progress, termWidth()-2)

	logMu.Lock()
	fmt.Fprint(os.Stderr, aClearLn+progress)
	logMu.Unlock()
}

func printSourceTable() {
	if !tty {
		return
	}
	logMu.Lock()
	defer logMu.Unlock()

	fmt.Fprint(os.Stderr, aClearLn)
	fmt.Fprintf(os.Stderr, "  %s\n",
		c(aGray, "┌─────────────┬─────────┬────────┬──────┬────────────┬───────┬──────────┐"))
	fmt.Fprintf(os.Stderr, "  %s %-13s%s %-9s%s %-7s%s %-5s%s %-10s%s %-6s%s %-9s%s\n",
		c(aGray, "│"), c(aBold, "Source"),
		c(aGray, "│"), c(aBold, "Requests"),
		c(aGray, "│"), c(aBold, "OK %"),
		c(aGray, "│"), c(aBold, "Act"),
		c(aGray, "│"), c(aBold, "Domains"),
		c(aGray, "│"), c(aBold, "Errs"),
		c(aGray, "│"), c(aBold, "Status"),
		c(aGray, "│"),
	)
	fmt.Fprintf(os.Stderr, "  %s\n",
		c(aGray, "├─────────────┼─────────┼────────┼──────┼────────────┼───────┼──────────┤"))

	for _, s := range sources {
		reqs := atomic.LoadUint64(&s.reqTotal)
		succ := atomic.LoadUint64(&s.reqSuccess)
		doms := atomic.LoadUint64(&s.domsFound)
		errs := atomic.LoadInt32(&s.errCount)
		inFlight := len(s.sem)
		pct := 0.0
		if reqs > 0 {
			pct = float64(succ) / float64(reqs) * 100
		}

		var state string
		if s.isDisabled() {
			state = c(aRed, "✖ DISABLED")
		} else if inFlight > 0 {
			state = c(aGreen, "✔ active  ")
		} else {
			state = c(aGray, "  idle    ")
		}

		errCol := c(aGray, fmt.Sprintf("%d", errs))
		if errs > 0 {
			errCol = c(aYellow, fmt.Sprintf("%d", errs))
		}

		pctCol := fmt.Sprintf("%.0f%%", pct)
		if pct < 50 {
			pctCol = c(aRed, pctCol)
		} else if pct < 80 {
			pctCol = c(aYellow, pctCol)
		} else {
			pctCol = c(aGreen, pctCol)
		}

		fmt.Fprintf(os.Stderr, "  %s %-13s%s %-9s%s %-15s%s %-5d%s %-10s%s %-14s%s %-17s%s\n",
			c(aGray, "│"), c(aCyan, s.name),
			c(aGray, "│"), fmtNum(reqs),
			c(aGray, "│"), pctCol,
			c(aGray, "│"), inFlight,
			c(aGray, "│"), c(aGreen, fmtNum(doms)),
			c(aGray, "│"), errCol,
			c(aGray, "│"), state,
			c(aGray, "│"),
		)
	}

	fmt.Fprintf(os.Stderr, "  %s\n",
		c(aGray, "└─────────────┴─────────┴────────┴──────┴────────────┴───────┴──────────┘"))
}

func statsLoop() {
	progTick := time.NewTicker(500 * time.Millisecond)
	tableTick := time.NewTicker(STATS_EVERY)
	defer progTick.Stop()
	defer tableTick.Stop()
	for {
		select {
		case <-progTick.C:
			printProgress()
		case <-tableTick.C:
			printSourceTable()
		}
	}
}

func printSummary() {
	ips := atomic.LoadUint64(&ipsProcessed)
	doms := atomic.LoadUint64(&domainsFound)
	elapsed := time.Since(start).Round(time.Second)
	rate := 0.0
	if elapsed.Seconds() > 0 {
		rate = float64(ips) / elapsed.Seconds()
	}

	if tty {
		logMu.Lock()
		fmt.Fprint(os.Stderr, aClearLn)
		fmt.Fprintf(os.Stderr, "\n  %s\n", c(aGray, "┌──────────────────────────────────┐"))
		fmt.Fprintf(os.Stderr, "  %s  %s  %s\n",
			c(aGray, "│"), c(aBold+aGreen, "       RUN COMPLETE               "), c(aGray, "│"))
		fmt.Fprintf(os.Stderr, "  %s\n", c(aGray, "├──────────────────────────────────┤"))
		fmt.Fprintf(os.Stderr, "  %s  IPs processed  %s%s\n",
			c(aGray, "│"), c(aWhite, fmt.Sprintf("%-16s", fmtNum(ips))), c(aGray, "│"))
		fmt.Fprintf(os.Stderr, "  %s  Domains found  %s%s\n",
			c(aGray, "│"), c(aGreen, fmt.Sprintf("%-16s", fmtNum(doms))), c(aGray, "│"))
		fmt.Fprintf(os.Stderr, "  %s  Throughput     %s%s\n",
			c(aGray, "│"), c(aCyan, fmt.Sprintf("%-16s", fmt.Sprintf("%.1f IP/s", rate))), c(aGray, "│"))
		fmt.Fprintf(os.Stderr, "  %s  Elapsed        %s%s\n",
			c(aGray, "│"), c(aYellow, fmt.Sprintf("%-16s", fmtDuration(elapsed))), c(aGray, "│"))
		fmt.Fprintf(os.Stderr, "  %s  Output         %s%s\n",
			c(aGray, "│"), c(aMagenta, fmt.Sprintf("%-16s", "domains.txt")), c(aGray, "│"))
		fmt.Fprintf(os.Stderr, "  %s\n\n", c(aGray, "└──────────────────────────────────┘"))
		logMu.Unlock()
	} else {
		fmt.Fprintf(os.Stderr, "done  IPs=%d  domains=%d  %.1f IP/s  elapsed=%s\n",
			ips, doms, rate, fmtDuration(elapsed))
	}
}

// ─────────────────────────────────────────────
//  WORKER
// ─────────────────────────────────────────────

func worker(jobs <-chan string, out chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for ip := range jobs {
		tried := make(map[string]bool, len(sources))
		queried := 0
		startIdx := atomic.AddUint64(&poolIdx, 1)

		for attempt := 0; attempt < len(pool) && queried < ROUNDS; attempt++ {
			src := pickSource(startIdx+uint64(attempt), tried)
			if src == nil {
				break
			}
			tried[src.name] = true
			queried++
			body := query(src, ip)
			if body != "" {
				n := parseBody(src.name, body, out)
				src.addDoms(n)
			}
		}
		atomic.AddUint64(&ipsProcessed, 1)
	}
}

// ─────────────────────────────────────────────
//  WRITER
// ─────────────────────────────────────────────

func writer(results chan string, done chan<- struct{}) {
	f, err := os.Create("domains.txt")
	if err != nil {
		logError("cannot create domains.txt: %v", err)
		panic(err)
	}
	defer f.Close()

	w := bufio.NewWriterSize(f, 256*1024)
	defer w.Flush()

	tick := time.NewTicker(FLUSH_EVERY)
	defer tick.Stop()

	for {
		select {
		case d, ok := <-results:
			if !ok {
				done <- struct{}{}
				return
			}
			w.WriteString(d + "\n")
			n := atomic.AddUint64(&domainsFound, 1)
			if n%10_000 == 0 {
				logInfo("milestone: %s domains found", c(aGreen+aBold, fmtNum(n)))
			}
			enrichSubdomains(d, results)
		case <-tick.C:
			w.Flush()
		}
	}
}

// ─────────────────────────────────────────────
//  MAIN
// ─────────────────────────────────────────────

func main() {
	printBanner()

	// Count IPs first for the progress bar.
	ipFile, err := os.Open("ips.txt")
	if err != nil {
		logError("cannot open ips.txt: %v", err)
		os.Exit(1)
	}
	var ipLines []string
	sc := bufio.NewScanner(ipFile)
	for sc.Scan() {
		ip := strings.TrimSpace(sc.Text())
		if ip != "" && !strings.HasPrefix(ip, "#") {
			ipLines = append(ipLines, ip)
		}
	}
	ipFile.Close()
	atomic.StoreUint64(&totalIPs, uint64(len(ipLines)))

	logInfo("loaded %s IPs  workers=%s  rounds/IP=%s  sources=%s",
		c(aWhite+aBold, fmtNum(uint64(len(ipLines)))),
		c(aCyan, fmt.Sprintf("%d", WORKERS)),
		c(aCyan, fmt.Sprintf("%d", ROUNDS)),
		c(aCyan, fmt.Sprintf("%d", len(sources))),
	)
	for _, s := range sources {
		logInfo("  %-12s  weight=%-2d  maxConc=%s",
			c(aCyan, s.name), s.weight, c(aGray, fmt.Sprintf("%d", cap(s.sem))))
	}

	jobs := make(chan string, JOB_BUF)
	results := make(chan string, RESULT_BUF)
	done := make(chan struct{})

	var wg sync.WaitGroup
	for i := 0; i < WORKERS; i++ {
		wg.Add(1)
		go worker(jobs, results, &wg)
	}

	go writer(results, done)
	go statsLoop()

	var closeOnce sync.Once
	closeJobs := func() { closeOnce.Do(func() { close(jobs) }) }
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		logWarn("signal received — draining pipeline...")
		closeJobs()
	}()

	for _, ip := range ipLines {
		jobs <- ip
	}
	closeJobs()

	wg.Wait()
	logInfo("workers done — flushing certspotter enrichment...")
	crtWg.Wait()

	close(results)
	<-done

	printSummary()
}
