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
	JOB_BUF       = 50_000
	RESULT_BUF    = 100_000
	HTTP_TIMEOUT  = 10 * time.Second
	MAX_RETRIES   = 2
	BACKOFF_BASE  = 400 * time.Millisecond
	ERR_THRESHOLD = 6
	ERR_RESET     = 90
)

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
}

var sources = []*Source{
	{name: "robtex",   weight: 1}, // instable, poids réduit
	{name: "rapiddns", weight: 4},
	{name: "crtsh_ip", weight: 1}, // lent, poids réduit
	{name: "webscan",  weight: 4},
}

func (s *Source) isDisabled() bool {
	t := atomic.LoadInt64(&s.disabledAt)
	if t == 0 {
		return false
	}
	if time.Now().Unix()-t > ERR_RESET {
		atomic.StoreInt64(&s.disabledAt, 0)
		atomic.StoreInt32(&s.errCount, 0)
		return false
	}
	return true
}

func (s *Source) fail() {
	if int(atomic.AddInt32(&s.errCount, 1)) >= ERR_THRESHOLD {
		atomic.StoreInt64(&s.disabledAt, time.Now().Unix())
	}
}

func (s *Source) ok() { atomic.StoreInt32(&s.errCount, 0) }

var pool []*Source
var poolIdx uint64

func init() {
	for _, s := range sources {
		for i := 0; i < s.weight; i++ {
			pool = append(pool, s)
		}
	}
}

func nextSource() *Source {
	n := uint64(len(pool))
	for i := 0; i < len(pool); i++ {
		s := pool[atomic.AddUint64(&poolIdx, 1)%n]
		if !s.isDisabled() {
			return s
		}
	}
	return sources[0]
}

// ─────────────────────────────────────────────
//  FETCHERS
// ─────────────────────────────────────────────

func doGET(u string) (string, error) {
	var lastErr error
	for i := 0; i <= MAX_RETRIES; i++ {
		if i > 0 {
			time.Sleep(BACKOFF_BASE * time.Duration(i))
		}
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
		req.Header.Set("Accept", "text/html,application/json,*/*")
		resp, err := httpClient.Do(req)
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
		if resp.StatusCode == 429 {
			time.Sleep(2 * time.Second)
			lastErr = fmt.Errorf("rate limited")
			continue
		}
		return string(b), nil
	}
	return "", lastErr
}

// doGETWithTimeout permet un timeout et nombre de retries personnalisés par source
func doGETWithTimeout(u string, timeout time.Duration, maxRetries int) (string, error) {
	cl := &http.Client{Timeout: timeout, Transport: httpClient.Transport}
	var lastErr error
	for i := 0; i <= maxRetries; i++ {
		if i > 0 {
			time.Sleep(BACKOFF_BASE * time.Duration(i*2))
		}
		req, _ := http.NewRequest("GET", u, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
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
		if resp.StatusCode == 429 || resp.StatusCode == 503 {
			time.Sleep(3 * time.Second)
			lastErr = fmt.Errorf("http %d", resp.StatusCode)
			continue
		}
		return string(b), nil
	}
	return "", lastErr
}

func fetchRobtex(ip string) (string, error) {
	// Robtex est lent/instable : timeout plus long, 1 seul retry
	return doGETWithTimeout("https://freeapi.robtex.com/pdns/reverse/"+ip, 15*time.Second, 1)
}

func fetchRapidDNS(ip string) (string, error) {
	return doGET("https://rapiddns.io/sameip/" + ip + "?full=1")
}

func fetchCRTSHByIP(ip string) (string, error) {
	// crt.sh est partagé et lent : timeout long, pas de retry agressif
	return doGETWithTimeout(fmt.Sprintf("https://crt.sh/?q=%s&output=json", ip), 20*time.Second, 1)
}

// webscan.cc — reverse IP JSON
func fetchWebscan(ip string) (string, error) {
	return doGET("https://api.webscan.cc/?action=query&ip=" + ip)
}

func query(s *Source, ip string) string {
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
	s = strings.TrimPrefix(s, "*.")
	if len(s) < 4 || !strings.Contains(s, ".") {
		return ""
	}
	if strings.ContainsAny(s, " \t<>\"'{}[]()") {
		return ""
	}
	return s
}

func emit(d string, out chan<- string) {
	d = clean(d)
	if d == "" {
		return
	}
	if _, loaded := seen.LoadOrStore(d, struct{}{}); !loaded {
		out <- d
	}
}

// Robtex NDJSON
func parseRobtex(body string, out chan<- string) {
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var obj map[string]interface{}
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}
		for _, k := range []string{"rrname", "rdata"} {
			if v, ok := obj[k].(string); ok {
				emit(v, out)
			}
		}
	}
}

// crt.sh JSON
type crtEntry struct {
	NameValue string `json:"name_value"`
}

func parseCRTSH(body string, out chan<- string) {
	var entries []crtEntry
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		return
	}
	for _, e := range entries {
		for _, line := range strings.Split(e.NameValue, "\n") {
			emit(line, out)
		}
	}
}

// RapidDNS HTML — domains in <td>
func parseRapidDNS(body string, out chan<- string) {
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
		emit(tok, out)
	}
}

// webscan.cc JSON: [{"domain":"...","title":"..."},...]
func parseWebscan(body string, out chan<- string) {
	var entries []struct {
		Domain string `json:"domain"`
	}
	if err := json.Unmarshal([]byte(body), &entries); err != nil {
		return
	}
	for _, e := range entries {
		d := e.Domain
		d = strings.TrimPrefix(d, "http://")
		d = strings.TrimPrefix(d, "https://")
		d = strings.SplitN(d, "/", 2)[0]
		emit(d, out)
	}
}

func parseBody(src string, body string, out chan<- string) {
	switch src {
	case "robtex":
		parseRobtex(body, out)
	case "rapiddns":
		parseRapidDNS(body, out)
	case "crtsh_ip":
		parseCRTSH(body, out)
	case "webscan":
		parseWebscan(body, out)
	}
}

// ─────────────────────────────────────────────
//  CRT.SH ENRICHMENT (apex domain)
// ─────────────────────────────────────────────

var crtSeen sync.Map
var crtSem = make(chan struct{}, 15)

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
	go func() {
		defer func() { <-crtSem }()
		body, err := doGET(fmt.Sprintf("https://crt.sh/?q=%%25.%s&output=json", apex))
		if err != nil {
			return
		}
		parseCRTSH(body, out)
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
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()
	for range t.C {
		ips := atomic.LoadUint64(&ipsProcessed)
		doms := atomic.LoadUint64(&domainsFound)
		elapsed := time.Since(start).Seconds()
		fmt.Printf("[stats] IPs=%d  domains=%d  %.1f IP/s  elapsed=%s\n",
			ips, doms, float64(ips)/elapsed, time.Since(start).Round(time.Second))
		for _, s := range sources {
			st := "OK"
			if s.isDisabled() {
				st = "DISABLED"
			}
			fmt.Printf("  %-12s  errs=%d  %s\n", s.name, atomic.LoadInt32(&s.errCount), st)
		}
	}
}

// ─────────────────────────────────────────────
//  WORKER
// ─────────────────────────────────────────────

func worker(jobs <-chan string, out chan<- string, wg *sync.WaitGroup) {
	defer wg.Done()
	for ip := range jobs {
		used := map[string]bool{}
		for round := 0; round < 2; round++ {
			src := nextSource()
			if used[src.name] {
				for _, s := range sources {
					if !used[s.name] && !s.isDisabled() {
						src = s
						break
					}
				}
			}
			used[src.name] = true
			body := query(src, ip)
			if body != "" {
				parseBody(src.name, body, out)
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
			atomic.AddUint64(&domainsFound, 1)
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
	fmt.Printf("[+] starting  workers=%d  sources=%d\n", WORKERS, len(sources))

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
		fmt.Fprintln(os.Stderr, "[-] cannot open ips.txt:", err)
		os.Exit(1)
	}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		ip := strings.TrimSpace(sc.Text())
		if ip != "" && !strings.HasPrefix(ip, "#") {
			jobs <- ip
		}
	}
	f.Close()
	close(jobs)

	wg.Wait()
	close(results)
	<-done

	fmt.Printf("\n[+] done  IPs=%d  domains=%d  time=%s\n",
		atomic.LoadUint64(&ipsProcessed),
		atomic.LoadUint64(&domainsFound),
		time.Since(start).Round(time.Second),
	)
}
