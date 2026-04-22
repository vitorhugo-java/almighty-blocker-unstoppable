# almighty-blocker-unstoppable

Continuously enforces redirect entries in the hosts file, with watchdog failover support.

## Build

1. Fill source URLs in env.json.
2. Build generated hosts data and binaries:

```bash
go run ./cmd/build
```

By default this generates:

- dist/almighty-blocker-windows-amd64.exe
- dist/almighty-blocker-linux-amd64

## Run as Console App

Windows (Administrator PowerShell):

```powershell
.\dist\almighty-blocker-windows-amd64.exe --role=primary --state-dir="$env:ProgramData\almighty-blocker"
```

Linux (root):

```bash
sudo ./dist/almighty-blocker-linux-amd64 --role=primary --state-dir=/var/lib/almighty-blocker
```

## Windows Service

Use the install script from an elevated PowerShell prompt:

```powershell
.\deploy\windows\install-service.ps1 -ExecutablePath .\dist\almighty-blocker-windows-amd64.exe -StartService
```

Useful commands:

```powershell
Get-Service almighty-blocker
Restart-Service almighty-blocker
Stop-Service almighty-blocker
```

Uninstall:

```powershell
.\deploy\windows\uninstall-service.ps1
```

Notes:

- The binary auto-detects when launched by the Windows Service Control Manager.
- Service should run with Administrator rights (LocalSystem by default via New-Service) to write hosts file.
- On primary startup, the app verifies the Windows service exists and is set to automatic startup; if missing, it recreates the service entry.

## Linux systemd Service

Use the installer as root:

```bash
chmod +x ./deploy/systemd/install-systemd.sh
sudo ./deploy/systemd/install-systemd.sh ./dist/almighty-blocker-linux-amd64 ./deploy/systemd/almighty-blocker.service
```

Useful commands:

```bash
sudo systemctl status almighty-blocker.service
sudo systemctl restart almighty-blocker.service
sudo journalctl -u almighty-blocker.service -f
```

The unit runs as root so it can enforce /etc/hosts.

On Linux primary startup, the app verifies a matching systemd unit exists in /etc/systemd/system, reloads systemd, and ensures the unit is enabled for boot.

## Runtime Flags

- --role: primary or watchdog (default primary)
- --state-dir: shared directory for role heartbeat files
- --service-name: Windows service name to bind when running under SCM

