package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/mux"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/net/websocket"
	"golang.org/x/time/rate"
)

// getEnvOrDefault returns the environment variable value or the default if not set
func getEnvOrDefault(envKey, defaultVal string) string {
	if val := os.Getenv(envKey); val != "" {
		return val
	}
	return defaultVal
}

func main() {
	// Support both environment variables and flags (env takes precedence)
	defaultPub := getEnvOrDefault("PORT", "5555")
	if !strings.HasPrefix(defaultPub, ":") {
		defaultPub = ":" + defaultPub
	}
	defaultPriv := getEnvOrDefault("ADMIN_PORT", "6666")
	if !strings.HasPrefix(defaultPriv, ":") {
		defaultPriv = ":" + defaultPriv
	}

	publicAddr := flag.String("pub", defaultPub, "listener address (env: PORT)")
	adminAddr := flag.String("priv", defaultPriv, "admin listener address (env: ADMIN_PORT)")
	adminKey := flag.String("adm-key", os.Getenv("ADMIN_KEY"), "admin api key (env: ADMIN_KEY) - REQUIRED for admin API")
	auditLogFile := flag.String("al", getEnvOrDefault("AUDIT_LOG", "connections.log"), "log file to store connection request (env: AUDIT_LOG)")
	flag.Parse()
	if *publicAddr == "" || *adminAddr == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}

	if auditLogFile != nil {
		var err error
		auditLog, err = os.OpenFile(*auditLogFile, os.O_APPEND|os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			log.Fatalf("failed to open connection log file %s: %v", *auditLogFile, err)
		}
	}

	wmux := websocket.Server{
		Handshake: bootHandshake,
		Handler:   handleWss,
	}

	if *adminKey == "" {
		log.Printf("WARNING: ADMIN_KEY not set - admin API will be disabled")
		log.Printf("Set ADMIN_KEY environment variable to enable admin API")
	}
	startAdmin(*adminAddr, *adminKey)
	r := mux.NewRouter()
	// Health check endpoint for Railway
	r.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	}).Methods("GET")
	r.Handle("/ws", wmux)
	// http.Handle("/cl/", http.StripPrefix("/cl", http.FileServer(http.Dir("./html"))))
	// r.PathPrefix("/cl/").Handler(http.StripPrefix("/cl", http.FileServer(http.Dir("./html"))))
	r.PathPrefix("/cl/").Handler(http.StripPrefix("/cl", FileServer(Dir("./html"))))

	srv := http.Server{
		Addr:    *publicAddr,
		Handler: r,
	}
	idleConnsClosed := make(chan struct{})
	go func() {
		sigint := make(chan os.Signal, 1)
		signal.Notify(sigint, os.Interrupt)
		<-sigint

		if err := srv.Shutdown(context.Background()); err != nil {
			log.Printf("HTTP server Shutdown: %v", err)
		}
		close(idleConnsClosed)
	}()

	log.Printf("server starts on: %s", *publicAddr)
	if err := srv.ListenAndServe(); err != http.ErrServerClosed {
		log.Fatalf("HTTP server ListenAndServe: %v", err)
	}

	<-idleConnsClosed
	wc := 0
	for {
		a := atomic.LoadInt64(&activeWebsocks)
		if a <= 0 {
			log.Printf("%d active websockets, terminating", a)
			break
		}
		time.Sleep(300 * time.Millisecond)
		wc++
		if wc%100 == 0 {
			log.Printf("%d websockets are active, waiting", a)
		}
	}
}

var activeWebsocks int64

func handleWss(wsconn *websocket.Conn) {
	var ac prometheus.Gauge
	defer func() {
		atomic.AddInt64(&activeWebsocks, -1)
		wsconn.Close()
		if ac != nil {
			ac.Dec()
		}
	}()
	atomic.AddInt64(&activeWebsocks, 1)
	id := wsconn.Config().Header.Get(reqIDHdr)
	l := logFromID(id)
	l.logf("request headers: %v", wsconn.Request().Header)
	blocked, ips := getIPAdress(wsconn)
	if blocked {
		l.logf("blocking ip: %v", ips)
		return
	}
	l.logf("handlewss from %v", ips)
	totalConnectionRequests.WithLabelValues(svcHost).Inc()
	err := wsconn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if err != nil {
		log.Printf("failed to set red deadline: %v", err)
		return
	}
	buf := make([]byte, 2048)
	_, err = wsconn.Read(buf)
	if err != nil {
		l.logf("failed to read connection msg: %v", err)
		return
	}
	var cr struct {
		Host string
		Port int
	}
	err = json.NewDecoder(bytes.NewBuffer(buf)).Decode(&cr)
	if err != nil {
		l.logf("failed to decode connection request [%s]: %v", buf, err)
		return
	}
	err = wsconn.SetReadDeadline(time.Time{})
	if err != nil {
		l.logf("failed to reset connection deadline: %v", err)
		return
	}
	l.logf("connecting to %s on port %d", cr.Host, cr.Port)
	writeAuditLog(ips[0], cr.Host, cr.Port, "connection request")
	if !isAllowedTarger(cr.Host) {
		l.logf("WARNING: connecting to %s is not allowed", cr.Host)
		return
	}
	var resp struct {
		Status string `json:"status"`
		Error  string `json:"error,omitempty"`
	}
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", cr.Host, cr.Port), 30*time.Second)
	if err != nil {
		l.logf("failed to connect: %v", err)
		writeAuditLog(ips[0], cr.Host, cr.Port, "connection failed")
		resp.Status = "failed"
		resp.Error = err.Error()
		if r, err := json.Marshal(resp); err != nil {
			l.logf("failed to marshall: %v", err)
		} else {
			if err := websocket.Message.Send(wsconn, r); err != nil {
				l.logf("failed to write status: %v", err)
			}
		}
		return
	}
	defer conn.Close()
	resp.Status = "ok"
	if r, err := json.Marshal(resp); err != nil {
		l.logf("failed to marshall: %v", err)
	} else {
		if err := websocket.Message.Send(wsconn, r); err != nil {
			l.logf("failed to write status: %v", err)
		}
	}
	totalConnections.WithLabelValues(svcHost).Inc()
	ac = activeConnections.WithLabelValues(svcHost)
	ac.Inc()
	writeAuditLog(ips[0], cr.Host, cr.Port, "connection established")
	wsconn.PayloadType = websocket.BinaryFrame

	cw, wsw := newLimters(conn, wsconn, l)

	done := make(chan struct{})

	go ping(l, wsconn, done)

	type conStat struct {
		dir   string
		err   error
		bytes int64
	}

	stats := make(chan conStat)

	go func() {
		n, err := io.Copy(&meteredWriter{
			w: cw,
			c: totalBytes.WithLabelValues(svcHost, "up"),
		}, wsconn)
		conn.Close()
		stats <- conStat{"up", err, n}
	}()
	go func() {
		n, err := io.Copy(&meteredWriter{
			w: wsw,
			c: totalBytes.WithLabelValues(svcHost, "down"),
		}, conn)
		wsconn.Close()
		stats <- conStat{"down", err, n}
	}()

	s1 := <-stats
	s2 := <-stats
	if s1.dir == "up" {
		l.logf("proxy finished copied (%d/%d)bytes anyerrors (%v,%v)", s1.bytes, s2.bytes, s1.err, s2.err)
		writeAuditLog(ips[0], cr.Host, cr.Port, fmt.Sprintf("proxy finished copied (%d/%d)bytes anyerrors (%v,%v)", s1.bytes, s2.bytes, s1.err, s2.err))
	} else {
		l.logf("proxy finished copied (%d/%d)bytes anyerrors (%v,%v)", s2.bytes, s1.bytes, s2.err, s1.err)
		writeAuditLog(ips[0], cr.Host, cr.Port, fmt.Sprintf("proxy finished copied (%d/%d)bytes anyerrors (%v,%v)", s2.bytes, s1.bytes, s2.err, s1.err))
	}
	close(done)
}

var auditLog io.Writer

func writeAuditLog(srcIP, dstIP string, dstPort int, msg string) {
	if auditLog == nil {
		return
	}
	_, err := auditLog.Write([]byte(fmt.Sprintf("%s,%s,%s,%d,%s\n", time.Now().UTC().Format(time.RFC3339Nano), srcIP, dstIP, dstPort, msg)))
	if err != nil {
		log.Printf("failed to write into connection log: %v", err)
	}
}

func ping(l logger, ws *websocket.Conn, done chan struct{}) {
	w, err := ws.NewFrameWriter(websocket.PingFrame)
	if err != nil {
		l.logf("failed to create pingwriter: %v", err)
		return
	}
	ticker := time.Tick(20 * time.Second)
	for {
		select {
		case <-ticker:
			_, err = w.Write(nil)
			if err != nil {
				l.logf("failed to write ping msg: %v", err)
				return
			}
		case <-done:
			return
		}
	}
}

type rCtx struct {
	headers http.Header
}

const reqIDHdr = "X-Request-ID"

func bootHandshake(config *websocket.Config, r *http.Request) error {
	// config.Protocol = []string{"binary"}
	u, err := uuid.NewRandom()
	id := "not-uuid"
	if err == nil {
		id = u.String()
	}
	config.Header = make(http.Header)
	config.Header.Set(reqIDHdr, id)

	// r.Header.Set("Access-Control-Allow-Origin", "*")
	// r.Header.Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE")

	return nil
}

var (
	blacklistedSources []string
	blacklistSrcMu     sync.RWMutex

	// Rate limiter with TTL support
	sourceRates   = map[string]*rateLimiterEntry{}
	sourceRatesMu sync.RWMutex
)

// rateLimiterEntry holds a rate limiter with last access time for TTL cleanup
type rateLimiterEntry struct {
	limiter    *rate.Limiter
	lastAccess time.Time
}

const (
	rateLimiterTTL      = 1 * time.Hour  // Remove entries not accessed for 1 hour
	rateLimiterCleanup  = 10 * time.Minute // Run cleanup every 10 minutes
)

func init() {
	// Start background cleanup goroutine for rate limiters
	go func() {
		ticker := time.NewTicker(rateLimiterCleanup)
		defer ticker.Stop()
		for range ticker.C {
			cleanupSourceRates()
		}
	}()
}

// cleanupSourceRates removes rate limiter entries that haven't been accessed within TTL
func cleanupSourceRates() {
	sourceRatesMu.Lock()
	defer sourceRatesMu.Unlock()

	now := time.Now()
	cleaned := 0
	for ip, entry := range sourceRates {
		if now.Sub(entry.lastAccess) > rateLimiterTTL {
			delete(sourceRates, ip)
			cleaned++
		}
	}
	if cleaned > 0 {
		log.Printf("Cleaned up %d expired rate limiter entries, %d remaining", cleaned, len(sourceRates))
	}
}

func getIPAdress(ws *websocket.Conn) (bool, []string) {
	// using sprintf as it panics locally
	var ips []string
	for _, h := range []string{"X-Forwarded-For", "X-Real-Ip"} {
		addresses := strings.Split(ws.Request().Header.Get(h), ",")
		for i := len(addresses) - 1; i >= 0; i-- {
			ip := strings.TrimSpace(addresses[i])
			ips = append(ips, ip)
		}
	}
	ips = append(ips, fmt.Sprintf("%v", ws.RemoteAddr()))

	// Check source blacklist
	blacklistSrcMu.RLock()
	for _, bi := range blacklistedSources {
		for _, ip := range ips {
			if strings.HasPrefix(ip, bi) {
				blacklistSrcMu.RUnlock()
				return true, ips
			}
		}
	}
	blacklistSrcMu.RUnlock()

	// Check/update rate limiter with TTL
	sourceRatesMu.Lock()
	entry := sourceRates[ips[0]]
	if entry == nil {
		entry = &rateLimiterEntry{
			limiter:    rate.NewLimiter(rate.Limit(1), 1),
			lastAccess: time.Now(),
		}
		sourceRates[ips[0]] = entry
	} else {
		entry.lastAccess = time.Now()
	}
	allowed := entry.limiter.Allow()
	sourceRatesMu.Unlock()

	return !allowed, ips
}

var (
	blacklistedTargets = []string{"localhost"}
	blacklistMu        sync.RWMutex

	// Private and reserved IP ranges (CIDR notation)
	privateNetworks = []string{
		"127.0.0.0/8",     // IPv4 loopback
		"10.0.0.0/8",      // RFC1918 private
		"172.16.0.0/12",   // RFC1918 private
		"192.168.0.0/16",  // RFC1918 private
		"169.254.0.0/16",  // Link-local
		"0.0.0.0/8",       // Current network
		"224.0.0.0/4",     // Multicast
		"240.0.0.0/4",     // Reserved
		"255.255.255.255/32", // Broadcast
		"::1/128",         // IPv6 loopback
		"fc00::/7",        // IPv6 unique local
		"fe80::/10",       // IPv6 link-local
		"ff00::/8",        // IPv6 multicast
		"::ffff:0:0/96",   // IPv4-mapped IPv6
	}
	parsedPrivateNetworks []*net.IPNet
)

func init() {
	// Pre-parse all private network CIDRs for efficiency
	for _, cidr := range privateNetworks {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("WARNING: Failed to parse private network CIDR %s: %v", cidr, err)
			continue
		}
		parsedPrivateNetworks = append(parsedPrivateNetworks, network)
	}
}

// isPrivateOrReservedIP checks if an IP address is private, loopback, or reserved
func isPrivateOrReservedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check against all private/reserved networks
	for _, network := range parsedPrivateNetworks {
		if network.Contains(ip) {
			return true
		}
	}

	// Additional checks using Go's built-in functions
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}

	return false
}

func isAllowedTarger(host string) bool {
	// Check explicit blacklist first
	blacklistMu.RLock()
	for _, h := range blacklistedTargets {
		if strings.EqualFold(host, h) {
			blacklistMu.RUnlock()
			return false
		}
	}
	blacklistMu.RUnlock()

	// Try to parse as IP address directly
	if ip := net.ParseIP(host); ip != nil {
		if isPrivateOrReservedIP(ip) {
			return false
		}
		return true
	}

	// If it's a hostname, resolve it and check all IPs
	ips, err := net.LookupIP(host)
	if err != nil {
		// If we can't resolve, allow it (will fail at connection time)
		// This prevents DNS-based blocking evasion while still allowing valid external hosts
		log.Printf("WARNING: Could not resolve hostname %s: %v - allowing connection attempt", host, err)
		return true
	}

	// Check all resolved IPs - block if ANY resolve to private/reserved
	for _, ip := range ips {
		if isPrivateOrReservedIP(ip) {
			log.Printf("Blocked connection to %s - resolves to private/reserved IP %s", host, ip)
			return false
		}
	}

	return true
}

var (
	freeLimit                 = 1024 * 1024 * 1024
	maxLimitedRate rate.Limit = 100 * 1024
	maxBurst                  = 64 * 1024
)

func newLimters(w1, w2 io.Writer, logger logger) (*limitedWriter, *limitedWriter) {
	l := rate.NewLimiter(maxLimitedRate, maxBurst)
	return &limitedWriter{w: w1, limiter: l, log: logger}, &limitedWriter{w: w2, limiter: l, log: logger}
}

type limitedWriter struct {
	w       io.Writer
	written int
	limiter *rate.Limiter
	log     logger
}

func (w *limitedWriter) Write(b []byte) (n int, err error) {
	if w.written > freeLimit {
		if err := w.limiter.WaitN(context.Background(), len(b)); err != nil {
			w.log.logf("limiter wait error: %v", err)
		}
	}
	w.written += len(b)
	return w.w.Write(b)
}

type meteredWriter struct {
	w io.Writer
	c prometheus.Counter
}

func (w *meteredWriter) Write(b []byte) (n int, err error) {
	n, err = w.w.Write(b)
	w.c.Add(float64(n))
	return n, err
}

type logger string

func (l logger) logf(fmt string, args ...interface{}) {
	log.Printf(string(l)+fmt, args...)
}

func newLogger() logger {
	u, err := uuid.NewRandom()
	id := "not-uuid"
	if err == nil {
		id = u.String()
	}
	return logFromID(id)
}

func logFromID(id string) logger {
	return logger(id[:8] + " ")
}
