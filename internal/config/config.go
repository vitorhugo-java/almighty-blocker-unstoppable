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
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/fsnotify/fsnotify"
)

// StringList accepts either a JSON array of strings or a single newline-separated
// JSON string.
type StringList []string

// UnmarshalJSON decodes either ["a", "b"] or "a\nb" into a StringList.
func (s *StringList) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		*s = nil
		return nil
	}

	var list []string
	if err := json.Unmarshal(data, &list); err == nil {
		*s = StringList(list)
		return nil
	}

	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	if raw == "" {
		*s = nil
		return nil
	}

	parts := strings.Split(raw, "\n")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		out = append(out, part)
	}

	*s = StringList(out)
	return nil
}

// EnvConfig is the schema for env.json.
//
// Java analogy: a POJO / record with @JsonProperty annotations.
// Go uses struct field tags instead of annotations.
type EnvConfig struct {
	// Sources lists URLs or local file paths from which block-lists are fetched.
	Sources StringList `json:"sources"`

	// SourceList is an alternative key for the same purpose as Sources.
	SourceList StringList `json:"sourceList"`

	// Files lists local file paths to include in the block-list.
	Files StringList `json:"files"`

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
	// Use net.SplitHostPort so that bare IPv6 addresses (which contain ":"
	// but no port) are handled correctly.
	for i, u := range cfg.UpstreamDNS {
		if _, _, err := net.SplitHostPort(u); err != nil {
			// No explicit port – append the standard DNS port.
			cfg.UpstreamDNS[i] = net.JoinHostPort(u, "53")
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
// The watcher monitors the parent directory rather than the file itself so that
// atomic rename-based saves (used by most editors and by the atomic-write
// pattern in hijack_linux.go) are reliably detected.  When an editor writes to a
// temporary file and then renames it over the config path, the OS emits a Create
// or Rename event for the config filename inside the directory – both of which
// trigger a reload here.  Watching the file directly would lose the watch after
// the first atomic rename because the original inode disappears.
//
// Java analogy: registering a WatchService listener on the parent Path with
// ENTRY_CREATE / ENTRY_MODIFY / ENTRY_DELETE kinds.
func (l *Loader) Watch(ctx context.Context, onChange func(EnvConfig)) error {
	// fsnotify.NewWatcher creates an OS-level inotify/kqueue/ReadDirectoryChangesW
	// watcher – the underlying mechanism varies per OS but the API is the same.
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return err
	}
	defer watcher.Close() // Always release OS resources – like try-with-resources in Java.

	// Watch the directory so that atomic rename-based writes are detected.
	dir := filepath.Dir(l.path)
	base := filepath.Base(l.path)
	if err := watcher.Add(dir); err != nil {
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
			// Only process events for our config file.
			if filepath.Base(event.Name) != base {
				continue
			}
			// React to writes, atomic rename-based writes (Write or Create on
			// the target path) and rename events (the file was moved away and
			// possibly replaced).
			if event.Has(fsnotify.Write) || event.Has(fsnotify.Create) || event.Has(fsnotify.Rename) {
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
