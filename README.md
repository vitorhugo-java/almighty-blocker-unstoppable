# Almighty Blocker Unstoppable

Almighty Blocker is a small daemon that continuously enforces a curated set of host redirects on the local machine and protects that configuration with an optional watchdog and self-defence features.

Key ideas:
- An embedded block list (generated at build time) is enforced inside the system hosts file between
  two markers: `# >>> almighty-blocker-unstoppable >>>` and `# <<< almighty-blocker-unstoppable <<<`.
- A tiny local DNS server (127.0.0.1:53) answers queries and forwards to upstream resolvers. When protection is enabled the DNS hijack guard ensures the system resolver still points to 127.0.0.1.
- A primary/watchdog pair provides automatic restart: the primary does the work, the watchdog monitors its heartbeat and restarts it if it crashes.
- Self-defence (camouflage, DNS guard, automatic service/unit registration) is compiled in by default. To disable these features build with the `noprotection` tag.

## Build

1. Edit `env.json` (see `env-example.json`) to configure remote sources and local files used to produce the compiled blocklist.
2. Generate the embedded hosts data and build binaries:

```bash
go run ./cmd/build
```

This command produces a Go constant (embeddedRedirectBlock) that is compiled into the binary. Typical outputs are placed under `dist/` (e.g. `dist/almighty-blocker-windows-amd64.exe`, `dist/almighty-blocker-linux-amd64`).

## Configuration (env.json)

Fields:
- `sources`: list of remote URLs to fetch plain text block lists from.
- `files`: list of local file paths to include when building the embedded blocklist.
- `upstreamDNS`: optional list of upstream DNS servers (host:port). If omitted the binary falls back to public resolvers (8.8.8.8:53, 1.1.1.1:53).

The running process also watches `env.json` at runtime and hot-reloads upstream DNS entries without restart.

## Runtime

Flags:
- `--role` — `primary` (default) or `watchdog`. Normal users only start the primary; the watchdog role is spawned and managed automatically.
- `--state-dir` — directory used to exchange heartbeat JSON files between roles (defaults to OS temp dir if empty).
- `--service-name` — OS service/unit identifier used when registering as a service; used by startup-registration and camouflage.

When protection is enabled (default build):
- The primary starts a local DNS server and waits until it is listening. Only after the DNS server is ready does the DNS hijack guard attempt to redirect system resolver entries to `127.0.0.1`.
- The primary parses the embedded blocklist and runs the hosts enforcement loop, which writes the block entries between the begin/end markers in the system hosts file.
- A watchdog process monitors the primary through heartbeat files in `--state-dir`. The watchdog may spawn or restart the primary when needed.

When protection is disabled (build with `-tags noprotection`):
- Self-defence features (camouflage, DNS hijack guard, watchdog envelope, automatic service/unit registration) are omitted at build time.
- The binary runs a simple single-process hosts enforcement loop (no watchdog, no process camouflage).

## Services / Installation

Linux (systemd):
- The primary will attempt to ensure a systemd unit file exists and enabled at `/etc/systemd/system/<service-name>.service`. The provided `deploy/systemd/install-systemd.sh` helper can be used to install the unit.
- The unit runs the binary as root so it can manage `/etc/hosts`.

Windows (Service Control Manager):
- On startup the primary checks for a Windows service with the configured name. If missing it will create or update the service using `sc.exe` and set `binPath` to include `--role=primary --state-dir=... --service-name="<name>"`.
- Use the scripts in `deploy/windows` to install/uninstall the service from an elevated PowerShell prompt.

Note: service registration requires administrative privileges.

## Developer notes

- The blocklist is embedded into the binary by `cmd/build` and consumed via `redirects.ParseLines` at runtime. If `lines` is empty the process exits with an error advising to run the build step.
- The DNS engine uses `internal/dnsengine` (miekg/dns) and supports `UpdateUpstreams(...)` via the config watcher.
- Camouflage randomizes process/service display name on supported platforms. This is a compile-time-enabled feature and can be removed by building with the `noprotection` tag.
- Markers used when editing the hosts file are constants defined in `main.go` (begin and end markers). Do not modify other hosts entries outside these markers.

## Troubleshooting

- If the DNS server fails to bind (permission or port in use), the binary will abort rather than redirect system DNS to a non-responsive address.
- Check journal logs on Linux: `sudo journalctl -u <service-name> -f`.
- On Windows, run the binary from an elevated PowerShell to see logs or check the event log / service manager for messages.

## Contributing

Pull requests should include tests where applicable and avoid changing build tags unexpectedly. For debugging, rebuild with `go run ./cmd/build` after updating `env.json` sources.

## License

See LICENSE.
