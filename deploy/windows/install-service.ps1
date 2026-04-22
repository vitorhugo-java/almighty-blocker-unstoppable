param(
    [string]$ServiceName = "almighty-blocker",
    [string]$DisplayName = "Almighty Blocker",
    [string]$Description = "Keeps hosts redirects enforced in background",
    [string]$ExecutablePath = ".\dist\almighty-blocker-windows-amd64.exe",
    [string]$StateDir = "$env:ProgramData\almighty-blocker",
    [switch]$StartService
)

$principal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script as Administrator."
}

$resolvedExe = (Resolve-Path $ExecutablePath).Path
New-Item -ItemType Directory -Path $StateDir -Force | Out-Null

$binaryPathName = '"{0}" --role=primary --state-dir="{1}"' -f $resolvedExe, $StateDir

$existing = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
if ($null -eq $existing) {
    New-Service -Name $ServiceName -BinaryPathName $binaryPathName -DisplayName $DisplayName -Description $Description -StartupType Automatic
} else {
    sc.exe config $ServiceName binPath= $binaryPathName start= auto | Out-Null
}

if ($StartService) {
    Start-Service -Name $ServiceName
}

Get-Service -Name $ServiceName | Select-Object Name, DisplayName, Status, StartType
