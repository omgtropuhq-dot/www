package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ─────────────────────────────────────────────
//  CONFIG
// ─────────────────────────────────────────────

const (
	// WORKERS matches total source capacity (sum of all maxConc).
	// With blocking semaphores, each worker holds exactly one source slot at a time;
	// keeping WORKERS ≈ total slots avoids both idle workers and semaphore pile-ups.
	WORKERS       = 80
	ROUNDS        = 3 // distinct sources queried per IP
	JOB_BUF       = 50_000
	RESULT_BUF    = 100_000
	HTTP_TIMEOUT  = 10 * time.Second
	MAX_RETRIES   = 2
	BACKOFF_BASE  = 400 * time.Millisecond
	ERR_THRESHOLD = 4  // fast disabling of unreliable sources
	ERR_RESET     = 60 // seconds before re-enabling a disabled source
	CRT_CONCUR    = 5
	STATS_EVERY   = 15 * time.Second
	FLUSH_EVERY   = 2 * time.Second
)

// ─────────────────────────────────────────────
//  LOGGER  (stderr · timestamp · levels · colors)
// ─────────────────────────────────────────────

var (
	tty   = isatty(os.Stderr)
	logMu sync.Mutex
)

func isatty(f *os.File) bool {
	fi, _ := f.Stat()
	return fi != nil && fi.Mode()&os.ModeCharDevice != 0
}

func ansi(s, code string) string {
	if !tty {
		return s
	}
	return code + s + "\033[0m"
}

func logLine(level, code, format string, a ...interface{}) {
	msg := fmt.Sprintf(format, a...)
	ts := time.Now().Format("15:04:05")
	logMu.Lock()
	fmt.Fprintf(os.Stderr, "%s %s %s\n", ansi(ts, "\033[90m"), ansi(level, code), msg)
	logMu.Unlock()
}

func logInfo(f string, a ...interface{})  { logLine("[INFO]", "\033[36m", f, a...) }
func logWarn(f string, a ...interface{})  { logLine("[WARN]", "\033[33m", f, a...) }
func logError(f string, a ...interface{}) { logLine("[ERR] ", "\033[31m", f, a...) }
func logStats(f string, a ...interface{}) { logLine("[STAT]", "\033[32m", f, a...) }

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
	name   string
	weight int
	// sem caps concurrent in-flight requests for this source.
	// Workers block on acquire — WORKERS is sized to match total capacity so
	// contention stays low and no worker starves indefinitely.
	sem        chan struct{}
	errCount   int32
	disabledAt int64
	// stats
	reqTotal   uint64
	reqSuccess uint64
	domsFound  uint64
}

func newSource(name string, weight, maxConc int) *Source {
	return &Source{name: name, weight: weight, sem: make(chan struct{}, maxConc)}
}

var sources = []*Source{
	//               name          weight  maxConc  (sum = 77 ≈ WORKERS)
	newSource("robtex",    1,   5),
	newSource("rapiddns",  3,  20),
	newSource("webscan",   3,  20),
	newSource("urlscan",   2,  12),
	newSource("viewdns",   3,  20), // works on residential IPs; cloud IPs get 403
	// crtsh_ip removed: always timeout/429 on this env, and crt.sh data is already
	// covered by enrichCRT() apex lookups which run independently of the worker pool.
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

// pickSource scans the weighted pool from startIdx and returns the first
// source that is neither disabled nor already in the skip set.
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
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Accept", "application/json, text/html, */*")
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

func fetchRapidDNS(ip string) (string, error) {
	return doGET("https://rapiddns.io/sameip/" + ip + "?full=1")
}

func fetchWebscan(ip string) (string, error) {
	return doGET("https://api.webscan.cc/?action=query&ip=" + ip)
}

// fetchViewDNS scrapes viewdns.info with browser-like headers to avoid WAF blocks.
func fetchViewDNS(ip string) (string, error) {
	cl := &http.Client{Timeout: HTTP_TIMEOUT, Transport: httpClient.Transport}
	u := "https://viewdns.info/reverseip/?host=" + ip
	req, err := http.NewRequest("GET", u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8")
	req.Header.Set("Accept-Language", "en-US,en;q=0.9")
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")
	req.Header.Set("Referer", "https://viewdns.info/")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	resp, err := cl.Do(req)
	if err != nil {
		return "", err
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, 5<<20))
	resp.Body.Close()
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 400 {
		return "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	body := string(b)
	if isHTML(body) && !strings.Contains(body, "<td>") {
		return "", fmt.Errorf("viewdns: empty or blocked page")
	}
	return body, nil
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

// query makes an HTTP request to source s for ip.
// Blocks until a concurrency slot is available (WORKERS ≈ total slots so
// contention is low), then performs the HTTP fetch.
func query(s *Source, ip string) string {
	s.sem <- struct{}{} // blocking acquire
	defer func() { <-s.sem }()

	atomic.AddUint64(&s.reqTotal, 1)
	var body string
	var err error
	switch s.name {
	case "robtex":
		body, err = fetchRobtex(ip)
	case "rapiddns":
		body, err = fetchRapidDNS(ip)
	case "webscan":
		body, err = fetchWebscan(ip)
	case "urlscan":
		body, err = fetchURLScan(ip)
	case "viewdns":
		body, err = fetchViewDNS(ip)
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
	s = strings.TrimSuffix(s, ".") // Robtex appends a trailing dot to FQDNs
	s = strings.TrimPrefix(s, "*.")
	if len(s) < 4 || !strings.Contains(s, ".") {
		return ""
	}
	if strings.ContainsAny(s, " \t<>\"'{}[]()") {
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
			continue // heartbeat / error line
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

func parseRapidDNS(body string, out chan<- string) int {
	count := 0
	for {
		start := strings.Index(body, "<td>")
		if start == -1 {
			break
		}
		body = body[start+4:]
		end := strings.Index(body, "</td>")
		if end == -1 {
			break
		}
		tok := strings.TrimSpace(body[:end])
		body = body[end+5:]
		if strings.Contains(tok, "<") || !strings.Contains(tok, ".") {
			continue
		}
		if emit(tok, out) {
			count++
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

// parseViewDNS scrapes the HTML table from viewdns.info reverseip.
// The results table contains two columns: domain name and last resolved date.
func parseViewDNS(body string, out chan<- string) int {
	count := 0
	// Find the results table (skip the first two header tables)
	tableStart := 0
	for i := 0; i < 3; i++ {
		idx := strings.Index(body[tableStart:], "<table")
		if idx == -1 {
			return 0
		}
		tableStart += idx + 1
	}
	section := body[tableStart:]
	tableEnd := strings.Index(section, "</table>")
	if tableEnd != -1 {
		section = section[:tableEnd]
	}
	for {
		start := strings.Index(section, "<td>")
		if start == -1 {
			break
		}
		section = section[start+4:]
		end := strings.Index(section, "</td>")
		if end == -1 {
			break
		}
		tok := strings.TrimSpace(section[:end])
		section = section[end+5:]
		// Skip the "Last Resolved" date column (contains digits and dashes only)
		if !strings.Contains(tok, "<") && strings.Contains(tok, ".") {
			if emit(tok, out) {
				count++
			}
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
	case "rapiddns":
		return parseRapidDNS(body, out)
	case "webscan":
		return parseWebscan(body, out)
	case "urlscan":
		return parseURLScan(body, out)
	case "viewdns":
		return parseViewDNS(body, out)
	}
	return 0
}

// ─────────────────────────────────────────────
//  CRT.SH ENRICHMENT  (apex wildcard query)
// ─────────────────────────────────────────────

var (
	crtSeen sync.Map
	crtSem  = make(chan struct{}, CRT_CONCUR)
	// crtWg prevents closing results while goroutines are still writing to it.
	crtWg sync.WaitGroup
)

func enrichCRT(domain string, out chan<- string) {
	parts := strings.Split(domain, ".")
	if len(parts) < 2 {
		return
	}
	apex := parts[len(parts)-2] + "." + parts[len(parts)-1]
	if _, loaded := crtSeen.LoadOrStore(apex, struct{}{}); loaded {
		return
	}
	// Add to WaitGroup before launching the goroutine to avoid a race with crtWg.Wait().
	// The semaphore is acquired inside the goroutine so the writer is never blocked here.
	crtWg.Add(1)
	go func() {
		crtSem <- struct{}{} // block inside goroutine, not in the writer
		defer func() {
			<-crtSem
			crtWg.Done()
		}()
		url := fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", apex)
		body, err := doGETWithTimeout(url, 25*time.Second, 1)
		if err != nil {
			logWarn("crtsh enrich %-30s → %v", apex, err)
			return
		}
		n := parseCRTSH(body, out)
		if n > 0 {
			logInfo("crtsh enrich %-30s → %d new domains", apex, n)
		}
	}()
}

// ─────────────────────────────────────────────
//  STATS
// ─────────────────────────────────────────────

var (
	ipsProcessed uint64
	domainsFound uint64
	start        = time.Now()
)

func statsLoop() {
	t := time.NewTicker(STATS_EVERY)
	defer t.Stop()
	for range t.C {
		ips := atomic.LoadUint64(&ipsProcessed)
		doms := atomic.LoadUint64(&domainsFound)
		elapsed := time.Since(start).Seconds()
		rate := 0.0
		if elapsed > 0 {
			rate = float64(ips) / elapsed
		}
		logStats("IPs=%-8d  domains=%-8d  %.1f IP/s  elapsed=%s",
			ips, doms, rate, time.Since(start).Round(time.Second))
		for _, s := range sources {
			state := ansi("OK      ", "\033[32m")
			if s.isDisabled() {
				state = ansi("DISABLED", "\033[31m")
			}
			reqs := atomic.LoadUint64(&s.reqTotal)
			succ := atomic.LoadUint64(&s.reqSuccess)
			sdoms := atomic.LoadUint64(&s.domsFound)
			inFlight := len(s.sem) // goroutines currently holding a slot
			pct := 0.0
			if reqs > 0 {
				pct = float64(succ) / float64(reqs) * 100
			}
			logStats("  %-12s  reqs=%-6d  ok=%-6d(%.0f%%)  active=%-3d  doms=%-8d  errs=%d  %s",
				s.name, reqs, succ, pct, inFlight, sdoms, atomic.LoadInt32(&s.errCount), state)
		}
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
			body := query(src, ip) // blocking — worker waits for a source slot
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
				logInfo("milestone: %d domains found", n)
			}
			enrichCRT(d, results)
		case <-tick.C:
			w.Flush()
		}
	}
}

// ─────────────────────────────────────────────
//  MAIN
// ─────────────────────────────────────────────

func main() {
	logInfo("starting  workers=%d  sources=%d  rounds/IP=%d", WORKERS, len(sources), ROUNDS)
	for _, s := range sources {
		logInfo("  %-12s  weight=%-2d  maxConc=%d", s.name, s.weight, cap(s.sem))
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

	// Graceful shutdown on SIGINT/SIGTERM: stop feeding jobs so the pipeline drains.
	var closeOnce sync.Once
	closeJobs := func() { closeOnce.Do(func() { close(jobs) }) }
	go func() {
		sig := make(chan os.Signal, 1)
		signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
		<-sig
		logWarn("signal received — draining pipeline...")
		closeJobs()
	}()

	f, err := os.Open("ips.txt")
	if err != nil {
		logError("cannot open ips.txt: %v", err)
		os.Exit(1)
	}
	sc := bufio.NewScanner(f)
	ipCount := 0
	for sc.Scan() {
		ip := strings.TrimSpace(sc.Text())
		if ip != "" && !strings.HasPrefix(ip, "#") {
			jobs <- ip
			ipCount++
		}
	}
	f.Close()
	logInfo("loaded %d IPs — waiting for workers...", ipCount)
	closeJobs()

	wg.Wait()
	logInfo("workers done — flushing crt.sh enrichment goroutines...")
	crtWg.Wait()

	close(results)
	<-done

	logInfo("done  IPs=%d  domains=%d  elapsed=%s",
		atomic.LoadUint64(&ipsProcessed),
		atomic.LoadUint64(&domainsFound),
		time.Since(start).Round(time.Second),
	)
}
