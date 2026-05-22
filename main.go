package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// ─────────────────────────────────────────────
//  CONFIG
// ─────────────────────────────────────────────

const (
	WORKERS       = 300
	ROUNDS        = 2 // distinct sources queried per IP
	JOB_BUF       = 50_000
	RESULT_BUF    = 100_000
	HTTP_TIMEOUT  = 10 * time.Second
	MAX_RETRIES   = 2
	BACKOFF_BASE  = 400 * time.Millisecond
	ERR_THRESHOLD = 6
	ERR_RESET     = 90 // seconds
	CRT_CONCUR    = 15
	STATS_EVERY   = 15 * time.Second
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
		MaxIdleConnsPerHost: 100,
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
	errCount   int32
	disabledAt int64
	// per-source stats
	reqTotal   uint64
	reqSuccess uint64
	domsFound  uint64
}

var sources = []*Source{
	{name: "robtex", weight: 1},
	{name: "rapiddns", weight: 4},
	{name: "crtsh_ip", weight: 1},
	{name: "webscan", weight: 4},
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

// nextSource returns a round-robin source starting from offset idx.
// Scanning linearly avoids spinning and distributes load fairly across workers.
func pickSources(startIdx uint64, skip map[string]bool) *Source {
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

// isHTML detects HTML error pages that some APIs return instead of JSON.
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
		return "", fmt.Errorf("robtex: HTML response (rate-limited?)")
	}
	return body, nil
}

func fetchRapidDNS(ip string) (string, error) {
	return doGET("https://rapiddns.io/sameip/" + ip + "?full=1")
}

func fetchCRTSHByIP(ip string) (string, error) {
	body, err := doGETWithTimeout(fmt.Sprintf("https://crt.sh/?q=%s&output=json", ip), 20*time.Second, 1)
	if err != nil {
		return "", err
	}
	if isHTML(body) {
		return "", fmt.Errorf("crtsh: HTML response (rate-limited?)")
	}
	return body, nil
}

func fetchWebscan(ip string) (string, error) {
	return doGET("https://api.webscan.cc/?action=query&ip=" + ip)
}

func query(s *Source, ip string) string {
	atomic.AddUint64(&s.reqTotal, 1)
	var body string
	var err error
	switch s.name {
	case "robtex":
		body, err = fetchRobtex(ip)
	case "rapiddns":
		body, err = fetchRapidDNS(ip)
	case "crtsh_ip":
		body, err = fetchCRTSHByIP(ip)
	case "webscan":
		body, err = fetchWebscan(ip)
	}
	if err != nil {
		s.fail()
		logWarn("%-10s %-16s → %v", s.name, ip, err)
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
	s = strings.TrimSuffix(s, ".") // Robtex FQDNs have a trailing dot
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

// parseRobtex handles NDJSON; skips heartbeat lines ({"time":N}, {"msg":"..."}).
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
		// heartbeat / error lines carry "msg" or only "time"
		if _, hasMsg := obj["msg"]; hasMsg {
			continue
		}
		for _, k := range []string{"rrname", "rdata"} {
			if raw, ok := obj[k]; ok {
				var v string
				if json.Unmarshal(raw, &v) == nil {
					if emit(v, out) {
						count++
					}
				}
			}
		}
	}
	return count
}

// crtEntry covers both the IP-query and the apex-wildcard responses.
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

func parseBody(src, body string, out chan<- string) int {
	switch src {
	case "robtex":
		return parseRobtex(body, out)
	case "rapiddns":
		return parseRapidDNS(body, out)
	case "crtsh_ip":
		return parseCRTSH(body, out)
	case "webscan":
		return parseWebscan(body, out)
	}
	return 0
}

// ─────────────────────────────────────────────
//  CRT.SH ENRICHMENT  (apex wildcard query)
// ─────────────────────────────────────────────

var (
	crtSeen sync.Map
	crtSem  = make(chan struct{}, CRT_CONCUR)
	// crtWg tracks goroutines so main can wait before closing results.
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
	crtSem <- struct{}{}
	crtWg.Add(1)
	go func() {
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
			pct := 0.0
			if reqs > 0 {
				pct = float64(succ) / float64(reqs) * 100
			}
			logStats("  %-12s  reqs=%-6d  ok=%-6d (%.0f%%)  domains=%-8d  errs=%d  %s",
				s.name, reqs, succ, pct, sdoms, atomic.LoadInt32(&s.errCount), state)
		}
	}
}

// ─────────────────────────────────────────────
//  WORKER
// ─────────────────────────────────────────────

func worker(jobs <-chan string, out chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for ip := range jobs {
		tried := make(map[string]bool, ROUNDS)
		queried := 0
		// Pick a starting offset unique to this IP slot to spread load across the pool.
		startIdx := atomic.AddUint64(&poolIdx, 1)
		for queried < ROUNDS {
			src := pickSources(startIdx+uint64(queried), tried)
			if src == nil {
				break // all sources tried or disabled
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

	tick := time.NewTicker(5 * time.Second)
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
	close(jobs)

	wg.Wait()
	logInfo("workers done — waiting for crt.sh enrichment goroutines...")
	crtWg.Wait() // must drain before closing results to avoid panic on write to closed chan

	close(results)
	<-done

	logInfo("done  IPs=%d  domains=%d  elapsed=%s",
		atomic.LoadUint64(&ipsProcessed),
		atomic.LoadUint64(&domainsFound),
		time.Since(start).Round(time.Second),
	)
}
