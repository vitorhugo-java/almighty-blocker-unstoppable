# Almighty Blocker Unstoppable

Almighty Blocker is a small daemon that continuously enforces a curated set of host redirects on the local machine and protects that configuration with an optional watchdog and self-defence features.

Key ideas:
- An embedded block list (generated at build time) is enforced inside the system hosts file between
  two markers: `# >>> almighty-blocker-unstoppable >>>` and `# <<< almighty-blocker-unstoppable <<<`.
- The daemon enforces configured external DNS servers on active interfaces and monitors for tampering.
- A primary/watchdog pair provides automatic restart: the primary does the work, the watchdog monitors its heartbeat and restarts it if it crashes.
- Self-defence (camouflage, DNS guard, automatic service/unit registration) is compiled in by default. To disable these features build with the `noprotection` tag.

## Build

1. Edit `env.json` (see `env-example.json`) to configure remote sources and local files used to produce the compiled blocklist.
2. Generate the embedded hosts data and build binaries:

```bash
go run ./cmd/build
```

This command produces Go constants (`generated_hosts.go` and `generated_env.go`) that are compiled into the binary. Typical outputs are placed under `dist/` (e.g. `dist/almighty-blocker-windows-amd64.exe`, `dist/almighty-blocker-linux-amd64`).

Useful build flags:
- `-refresh-tor-ips`: updates `torEntryIPs` from Onionoo before building.
- `-tor-ip-limit`: max number of unique IP entries kept in `torEntryIPs` (default `0`, unlimited).

Example:

```bash
go run ./cmd/build -refresh-tor-ips -tor-ip-limit 1500 -no-protection
```

## Configuration (env.json)

Fields:
- `sources`: list of remote URLs to fetch plain text block lists from.
- `files`: list of local file paths to include when building the embedded blocklist.
- `DNS`: list of external DNS servers to enforce on the host adapters (for example `"1.1.1.1"`, `"1.0.0.1"`).
- `upstreamDNS`: legacy compatibility field. If `DNS` is omitted, values from `upstreamDNS` are used when possible.
- `torEntryIPs`: optional list of IPv4 addresses of Tor guard/entry nodes to block at the network level. See [Managing torEntryIPs](#managing-torentryips) for how to populate this list.
- `blockAddress`: optional manual block list. Accepts domains and IPs. IPs are blocked directly by firewall. Domains are periodically resolved and resulting IPs are blocked by firewall.

Example `DNS`:

```json
[
  "1.1.1.1",
  "1.0.0.1"
]
```

`sources` and `files` may be empty. In that case the build still succeeds and generates an empty embedded blocklist.

`env.json` is embedded into the binary at build time and loaded from memory at runtime. The service does not depend on an external `env.json` file after build.

## Managing torEntryIPs

The `torEntryIPs` field lists IP addresses of Tor guard/entry nodes. Blocking these prevents devices on the network from establishing connections to the Tor network.

**Manual:** edit `env.json` and add IP address strings to the `torEntryIPs` array.

**From Onionoo (recommended):** fetch the current list of running guard relays and extract IP addresses:

```bash
curl -s 'https://onionoo.torproject.org/details?flag=Guard&running=true&fields=or_addresses' \
  | jq -r '..|strings|scan("(\\d{1,3}(?:\\.\\d{1,3}){3})")' \
  | awk -F. '$1<=255&&$2<=255&&$3<=255&&$4<=255' \
  | sort -u
```

Copy the output into the `torEntryIPs` array in `env.json`.

**Automation:** schedule a cron job (Linux) or Windows Scheduled Task to refresh the list periodically and rebuild so the binary embeds the updated `env.json`.

You can also refresh automatically via builder: `go run ./cmd/build -refresh-tor-ips`.

Notes:
- Use only plain IP addresses without ports (e.g. `"1.2.3.4"`, `"2001:db8::1"`).
- The Tor relay list changes frequently; refreshing weekly or daily is recommended.

## Runtime

Flags:
- `--role` — `primary` (default) or `watchdog`. Normal users only start the primary; the watchdog role is spawned and managed automatically.
- `--state-dir` — directory used to exchange heartbeat JSON files between roles (defaults to OS temp dir if empty).
- `--service-name` — OS service/unit identifier used when registering as a service; used by startup-registration and camouflage.

When protection is enabled (default build):
- The primary enforces configured DNS servers on the OS network interfaces.
- The primary applies firewall blocks from `torEntryIPs` and `blockAddress` (IPs directly, domains via resolved IPs).
- A watchdog process monitors the primary through heartbeat files in `--state-dir`. The watchdog may spawn or restart the primary when needed.

When protection is disabled (build with `-tags noprotection`):
- Self-defence features (camouflage, DNS hijack guard, watchdog envelope, automatic service/unit registration) are omitted at build time.
- The binary applies DNS + firewall configuration once at startup and then only logs if settings are changed or removed.

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
- DNS enforcement uses `internal/dnshijack` and firewall enforcement uses `internal/firewallguard`.
- Camouflage randomizes process/service display name on supported platforms. This is a compile-time-enabled feature and can be removed by building with the `noprotection` tag.
- Markers used when editing the hosts file are constants defined in `main.go` (begin and end markers). Do not modify other hosts entries outside these markers.

## Troubleshooting

- If the DNS server fails to bind (permission or port in use), the binary will abort rather than redirect system DNS to a non-responsive address.
- On Windows, if DNS requests time out to `127.0.0.1` while the process is running, check for port 53 conflicts (commonly `SharedAccess` / Internet Connection Sharing) and stop/disable that service from an elevated shell.
- If domain blocking works in `nslookup` but not in apps or `ping`, verify IPv6 DNS settings too. Set IPv6 DNS to `::1` (or disable IPv6 DNS on the adapter), because many clients prefer IPv6 resolvers and can bypass `127.0.0.1`.
- Check journal logs on Linux: `sudo journalctl -u <service-name> -f`.
- On Windows, run the binary from an elevated PowerShell to see logs or check the event log / service manager for messages.

## Contributing

Pull requests should include tests where applicable and avoid changing build tags unexpectedly. For debugging, rebuild with `go run ./cmd/build` after updating `env.json` sources.

## License

See LICENSE.
