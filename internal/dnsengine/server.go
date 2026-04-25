// Package dnsengine implements a local DNS server that listens on 127.0.0.1:53
// and forwards every query to a configurable list of upstream resolvers.
//
// Java analogy: think of this as a Netty-based UDP server with a handler pipeline.
// The miekg/dns library plays the role of Netty in the DNS world.
package dnsengine

import (
	"context"
	"crypto/tls"
	"log/slog"
	"net"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"almighty-blocker-unstoppable/internal/logger"
)

// defaultTimeout is how long we wait for a single upstream resolver to respond
// before trying the next one in the list.
const defaultTimeout = 3 * time.Second

// bootstrapResolver bypasses the local DNS listener when the process needs to
// resolve upstream hostnames (for example dns.google in DoH URLs). Without this,
// the resolver can recurse into itself and fail all non-blocked queries.
var bootstrapResolver = &net.Resolver{
	PreferGo: true,
	Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		d := &net.Dialer{Timeout: defaultTimeout}
		return d.DialContext(ctx, "udp", "1.1.1.1:53")
	},
}

// Server is a local UDP DNS server that proxies queries to upstream resolvers.
//
// Java analogy: a @Service class that implements InitializingBean / DisposableBean
// for lifecycle management, backed by an ExecutorService for concurrency.
type Server struct {
	listenAddr string

	// mu guards the upstreams slice so it can be safely swapped at runtime
	// when the configuration is hot-reloaded.
	// Java analogy: ReentrantReadWriteLock protecting a volatile field.
	mu        sync.RWMutex
	upstreams []string

	// blockDomains stores lower-cased domain names without trailing dots.
	blockDomains map[string]struct{}
	// blockIPs stores normalized IP strings to sinkhole if seen in answers.
	blockIPs map[string]struct{}

	// readyCh is closed by NotifyStartedFunc once the server successfully
	// binds its listen address.  Callers can wait on Ready() to confirm the
	// server is up before routing system DNS to it.
	readyCh chan struct{}

	log *slog.Logger
}

// New creates a Server but does not start it yet.
//
// Java analogy: a constructor that injects dependencies.  Call Run() to start.
func New(listenAddr string, upstreams []string) *Server {
	return &Server{
		listenAddr: listenAddr,
		upstreams:  normaliseUpstreams(upstreams),
		blockDomains: make(map[string]struct{}),
		blockIPs:     make(map[string]struct{}),
		log:        logger.New("dns-server"),
		readyCh:    make(chan struct{}),
	}
}

// Ready returns a channel that is closed once the server has successfully bound
// its listen address.  Use this to synchronise dependent components (e.g. DNS
// hijack guard) so they only activate after the listener is confirmed running.
//
// Java analogy: a CompletableFuture<Void> that completes when the server starts.
func (s *Server) Ready() <-chan struct{} {
	return s.readyCh
}

// UpdateUpstreams atomically replaces the list of upstream resolvers.
// Safe to call from any goroutine while the server is running.
//
// Java analogy: a thread-safe setter that triggers no restart – the next
// incoming query will automatically use the new list.
func (s *Server) UpdateUpstreams(upstreams []string) {
	s.mu.Lock()
	s.upstreams = normaliseUpstreams(upstreams)
	s.mu.Unlock()
	s.log.Info("upstream DNS servers updated", "servers", s.upstreams)
}

// UpdateBlockAddress atomically replaces the manual block rules.
func (s *Server) UpdateBlockAddress(values []string) {
	domains := make(map[string]struct{})
	ips := make(map[string]struct{})

	for _, raw := range values {
		item := strings.TrimSpace(raw)
		if item == "" {
			continue
		}

		if ip := net.ParseIP(strings.Trim(item, "[]")); ip != nil {
			ips[ip.String()] = struct{}{}
			continue
		}

		domain := normalizeDomain(item)
		if domain != "" {
			domains[domain] = struct{}{}
		}
	}

	s.mu.Lock()
	s.blockDomains = domains
	s.blockIPs = ips
	s.mu.Unlock()

	s.log.Info("DNS block rules updated", "domains", len(domains), "ips", len(ips))
}

// Run starts the DNS server and blocks until ctx is cancelled.
// It returns any non-context error that stops the server.
//
// Java analogy: server.start() followed by awaitTermination() – a blocking call
// that drives the event loop until a shutdown signal arrives.
func (s *Server) Run(ctx context.Context) error {
	// dns.NewServeMux is analogous to http.NewServeMux – it routes DNS questions
	// to handler functions based on the query name pattern.
	mux := dns.NewServeMux()

	// Register a catch-all handler for the DNS root zone (".").
	// This means every query, regardless of the domain, is handled by handleDNS.
	mux.HandleFunc(".", s.handleDNS)

	srv := &dns.Server{
		Addr:         s.listenAddr,
		Net:          "udp",    // Use UDP – the default transport for DNS.
		Handler:      mux,
		ReadTimeout:  defaultTimeout,
		WriteTimeout: defaultTimeout,
		// NotifyStartedFunc is called by miekg/dns as soon as the socket is
		// bound and the server is ready to accept queries.  Closing readyCh
		// here unblocks any caller waiting on Ready() before enabling DNS
		// hijack enforcement.
		NotifyStartedFunc: func() { close(s.readyCh) },
	}

	// errCh receives the error from ListenAndServe when the server exits.
	// Buffered with size 1 so the goroutine never blocks on send.
	// Java analogy: a CompletableFuture<Void> returned by executor.submit().
	errCh := make(chan error, 1)
	go func() {
		s.log.Info("DNS server listening", "addr", s.listenAddr)
		errCh <- srv.ListenAndServe()
	}()

	select {
	case <-ctx.Done():
		// ctx.Done() is closed when the parent context is cancelled (e.g. SIGTERM).
		// Java analogy: a Future.cancel() or ExecutorService.shutdown() signal.
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.ShutdownContext(shutCtx); err != nil {
			s.log.Error("DNS server shutdown error", "error", err)
		}
		return nil

	case err := <-errCh:
		return err
	}
}

// handleDNS processes a single inbound DNS query.
// It forwards the query to each configured upstream in order, returning on the
// first successful response.
//
// Java analogy: a Netty ChannelInboundHandlerAdapter.channelRead() override,
// or a servlet's doGet() method in a blocking model.
func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		// Malformed request – no questions attached.
		dns.HandleFailed(w, r)
		return
	}

	q := r.Question[0]

	// Log the query with the domain name masked for privacy.
	// Even in DEBUG mode we avoid storing raw queries in log files.
	s.log.Debug("DNS query",
		"name", logger.MaskDomain(q.Name),
		"type", dns.TypeToString[q.Qtype],
	)

	// Take snapshots under a read-lock so we don't
	// block writers (hot-reload) for longer than necessary.
	s.mu.RLock()
	upstreams := make([]string, len(s.upstreams))
	copy(upstreams, s.upstreams)
	blockDomains := make(map[string]struct{}, len(s.blockDomains))
	for domain := range s.blockDomains {
		blockDomains[domain] = struct{}{}
	}
	blockIPs := make(map[string]struct{}, len(s.blockIPs))
	for ip := range s.blockIPs {
		blockIPs[ip] = struct{}{}
	}
	s.mu.RUnlock()

	if isBlockedDomain(q.Name, blockDomains) {
		s.log.Info("blocked DNS query by domain rule", "name", logger.MaskDomain(q.Name))
		writeBlockedResponse(w, r)
		return
	}

	if len(upstreams) == 0 {
		s.log.Warn("no upstream DNS servers configured")
		dns.HandleFailed(w, r)
		return
	}

	for _, upstream := range upstreams {
		resp, err := exchangeWithUpstream(r, upstream)
		if err != nil {
			s.log.Debug("upstream query failed", "upstream", upstream, "error", err)
			continue // Try next upstream – like iterating a fallback chain in Java.
		}

		if shouldSinkholeByAnswer(resp, blockIPs) {
			s.log.Info("blocked DNS query by IP rule", "name", logger.MaskDomain(q.Name))
			writeBlockedResponse(w, r)
			return
		}

		// Copy the client's request ID into the response so the client can
		// correlate the answer to the question it asked.
		resp.Id = r.Id

		if writeErr := w.WriteMsg(resp); writeErr != nil {
			s.log.Error("write DNS response failed", "error", writeErr)
		}
		return
	}

	// All upstreams failed.
	s.log.Warn("all upstream DNS servers failed",
		"name", logger.MaskDomain(q.Name),
		"upstreams", len(upstreams),
	)
	dns.HandleFailed(w, r)
}

func exchangeWithUpstream(req *dns.Msg, upstream string) (*dns.Msg, error) {
	netType, address := resolveUpstreamTransport(upstream)
	client := &dns.Client{Timeout: defaultTimeout, Net: netType}
	client.Dialer = &net.Dialer{Timeout: defaultTimeout, Resolver: bootstrapResolver}

	if netType == "tcp-tls" {
		host := hostFromAddress(address)
		if host != "" && net.ParseIP(host) == nil {
			client.TLSConfig = &tls.Config{ServerName: host}
		}
	}

	resp, _, err := client.Exchange(req, address)
	return resp, err
}

func resolveUpstreamTransport(upstream string) (string, string) {
	upstream = strings.TrimSpace(upstream)
	if upstream == "" {
		return "udp", ""
	}

	if strings.Contains(upstream, "://") {
		u, err := url.Parse(upstream)
		if err == nil {
			scheme := strings.ToLower(u.Scheme)
			switch scheme {
			case "udp":
				return "udp", normalizeHostPort(u.Host, "53")
			case "tcp":
				return "tcp", normalizeHostPort(u.Host, "53")
			case "tls":
				return "tcp-tls", normalizeHostPort(u.Host, "853")
			case "https":
				if u.Path == "" || u.Path == "/" {
					u.Path = "/dns-query"
				}
				return "https", u.String()
			}
		}
	}

	return "udp", normalizeHostPort(upstream, "53")
}

func normalizeHostPort(host string, defaultPort string) string {
	host = strings.TrimSpace(host)
	if host == "" {
		return ""
	}

	if _, _, err := net.SplitHostPort(host); err == nil {
		return host
	}

	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	}

	return net.JoinHostPort(host, defaultPort)
}

func hostFromAddress(address string) string {
	h, _, err := net.SplitHostPort(address)
	if err != nil {
		return ""
	}
	return strings.TrimPrefix(strings.TrimSuffix(h, "]"), "[")
}

func normalizeDomain(value string) string {
	value = strings.TrimSpace(strings.ToLower(value))
	value = strings.TrimSuffix(value, ".")
	return value
}

func isBlockedDomain(queryName string, blocked map[string]struct{}) bool {
	if len(blocked) == 0 {
		return false
	}

	name := normalizeDomain(queryName)
	if name == "" {
		return false
	}

	for domain := range blocked {
		if name == domain || strings.HasSuffix(name, "."+domain) {
			return true
		}
	}

	return false
}

func shouldSinkholeByAnswer(resp *dns.Msg, blockedIPs map[string]struct{}) bool {
	if len(blockedIPs) == 0 || resp == nil {
		return false
	}

	for _, answer := range resp.Answer {
		switch rr := answer.(type) {
		case *dns.A:
			if _, ok := blockedIPs[rr.A.String()]; ok {
				return true
			}
		case *dns.AAAA:
			if _, ok := blockedIPs[rr.AAAA.String()]; ok {
				return true
			}
		}
	}

	return false
}

func writeBlockedResponse(w dns.ResponseWriter, req *dns.Msg) {
	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true
	msg.Rcode = dns.RcodeNameError // NXDOMAIN

	_ = w.WriteMsg(msg)
}

// normaliseUpstreams ensures every entry in the list has an explicit port.
func normaliseUpstreams(in []string) []string {
	out := make([]string, 0, len(in))
	for _, u := range in {
		u = strings.TrimSpace(u)
		if u == "" {
			continue
		}
		_, normalized := resolveUpstreamTransport(u)
		if normalized == "" {
			continue
		}

		if strings.Contains(u, "://") {
			uParsed, err := url.Parse(u)
			if err == nil {
				scheme := strings.ToLower(uParsed.Scheme)
				switch scheme {
				case "udp", "tcp", "tls":
					uParsed.Host = normalized
					uParsed.Path = ""
					uParsed.RawQuery = ""
					uParsed.Fragment = ""
					out = append(out, uParsed.String())
					continue
				case "https":
					if uParsed.Path == "" || uParsed.Path == "/" {
						uParsed.Path = "/dns-query"
					}
					out = append(out, uParsed.String())
					continue
				}
			}
		}

		out = append(out, normalized)
	}
	return out
}
