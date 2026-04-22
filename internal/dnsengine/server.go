// Package dnsengine implements a local DNS server that listens on 127.0.0.1:53
// and forwards every query to a configurable list of upstream resolvers.
//
// Java analogy: think of this as a Netty-based UDP server with a handler pipeline.
// The miekg/dns library plays the role of Netty in the DNS world.
package dnsengine

import (
	"context"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"

	"almighty-blocker-unstoppable/internal/logger"
)

// defaultTimeout is how long we wait for a single upstream resolver to respond
// before trying the next one in the list.
const defaultTimeout = 3 * time.Second

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

	log *slog.Logger
}

// New creates a Server but does not start it yet.
//
// Java analogy: a constructor that injects dependencies.  Call Run() to start.
func New(listenAddr string, upstreams []string) *Server {
	return &Server{
		listenAddr: listenAddr,
		upstreams:  normaliseUpstreams(upstreams),
		log:        logger.New("dns-server"),
	}
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

	// Take a snapshot of the upstreams slice under a read-lock so we don't
	// block writers (hot-reload) for longer than necessary.
	s.mu.RLock()
	upstreams := make([]string, len(s.upstreams))
	copy(upstreams, s.upstreams)
	s.mu.RUnlock()

	if len(upstreams) == 0 {
		s.log.Warn("no upstream DNS servers configured")
		dns.HandleFailed(w, r)
		return
	}

	// dns.Client is stateless and safe to create per request.
	// Java analogy: a new HttpClient per request (cheap in Go; goroutines are ~2 KB).
	c := &dns.Client{Timeout: defaultTimeout}

	for _, upstream := range upstreams {
		resp, _, err := c.Exchange(r, upstream)
		if err != nil {
			s.log.Debug("upstream query failed", "upstream", upstream, "error", err)
			continue // Try next upstream – like iterating a fallback chain in Java.
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

// normaliseUpstreams ensures every entry in the list has an explicit port.
func normaliseUpstreams(in []string) []string {
	out := make([]string, 0, len(in))
	for _, u := range in {
		if u == "" {
			continue
		}
		if _, _, err := net.SplitHostPort(u); err != nil {
			// No port present – append the standard DNS port.
			u = net.JoinHostPort(u, "53")
		}
		out = append(out, u)
	}
	return out
}
