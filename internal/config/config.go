// Package config loads the application configuration from env.json and
// hot-reloads it whenever the file changes, using fsnotify.
//
// Java analogy: a Spring @ConfigurationProperties bean annotated with @RefreshScope,
// combined with a FileSystemWatcher that triggers a context refresh.
package config

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
)

// EnvConfig is the schema for env.json.
//
// Java analogy: a POJO / record with @JsonProperty annotations.
// Go uses struct field tags instead of annotations.
type EnvConfig struct {
	// Sources lists URLs or local file paths from which block-lists are fetched.
	Sources []string `json:"sources"`

	// SourceList is an alternative key for the same purpose as Sources.
	SourceList []string `json:"sourceList"`

	// Files lists local file paths to include in the block-list.
	Files []string `json:"files"`

	// UpstreamDNS is the ordered list of upstream DNS resolvers the local DNS
	// server will forward queries to.  Each entry must be in "host:port" or bare
	// "host" form (port 53 is assumed when omitted).
	//
	// Example: ["8.8.8.8:53", "1.1.1.1:53"]
	UpstreamDNS []string `json:"upstreamDNS"`
}

// Loader owns the live configuration value and keeps it in sync with the file on disk.
//
// Java analogy: a singleton @Service class holding a volatile reference to the latest
// config object and registering a file-change listener via WatchService.
type Loader struct {
	mu   sync.RWMutex // protects cfg; RWMutex = ReadWriteLock in Java
	cfg  EnvConfig
	path string
	log  *slog.Logger
}

// NewLoader creates a Loader and performs the first synchronous load from path.
// Returns an error when the file cannot be read or parsed.
//
// Java analogy: @PostConstruct method that reads application.yml on startup.
func NewLoader(path string) (*Loader, error) {
	l := &Loader{
		path: path,
		log:  slog.Default().With("component", "config"),
	}
	if err := l.reload(); err != nil {
		return nil, err
	}
	return l, nil
}

// Config returns a snapshot of the current configuration.
// Thread-safe: multiple goroutines may call this concurrently.
//
// Java analogy: a synchronized getter method returning a defensive copy.
func (l *Loader) Config() EnvConfig {
	// RLock allows multiple concurrent readers – same semantics as Java ReadWriteLock.
	l.mu.RLock()
	defer l.mu.RUnlock()
	return l.cfg
}

// reload reads the file from disk and updates the in-memory configuration.
func (l *Loader) reload() error {
	data, err := os.ReadFile(l.path)
	if err != nil {
		return err
	}
	var cfg EnvConfig
	if err := json.Unmarshal(data, &cfg); err != nil {
		return err
	}

	// Normalise upstream entries – add ":53" when no port was specified.
	for i, u := range cfg.UpstreamDNS {
		if !strings.Contains(u, ":") {
			cfg.UpstreamDNS[i] = u + ":53"
		}
	}

	// Write lock while replacing the value.
	l.mu.Lock()
	l.cfg = cfg
	l.mu.Unlock()
	return nil
}

// Watch starts a background file-watcher and calls onChange whenever env.json is
// modified.  It blocks until ctx is cancelled.
//
// Java analogy: registering a WatchService listener in a separate thread / Executor.
// In Go, goroutines are the lightweight equivalent of Java threads.
func (l *Loader) Watch(ctx context.Context, onChange func(EnvConfig)) error {
	// fsnotify.NewWatcher creates an OS-level inotify/kqueue/ReadDirectoryChangesW
	// watcher – the underlying mechanism varies per OS but the API is the same.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close() // Always release OS resources – like try-with-resources in Java.

	if err := watcher.Add(l.path); err != nil {
		return err
	}

	l.log.Info("watching config file", "path", l.path)

	for {
		// select is Go's equivalent of Java's switch on multiple blocking channels.
		select {
		case <-ctx.Done():
			// Context cancelled (e.g. SIGTERM received) – stop watching.
			return nil

		case event, ok := <-watcher.Events:
			if !ok {
				return nil // Channel closed – watcher was shut down.
			}
			// React to writes and atomic rename-based writes (common in editors).
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) {
				if err := l.reload(); err != nil {
					l.log.Error("config reload failed", "error", err)
					continue
				}
				l.log.Info("config reloaded")
				onChange(l.Config())
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return nil
			}
			l.log.Error("fsnotify error", "error", err)
		}
	}
}
