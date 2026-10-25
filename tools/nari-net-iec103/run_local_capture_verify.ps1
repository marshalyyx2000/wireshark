# Capture loopback traffic while NARI master/slave exchange, then verify with tshark.
param(
    [string]$HostAddr = "127.0.0.1",
    [int]$DurationSec = 25,
    [string]$Tshark = "",
    [string]$Dumpcap = ""
)

$ErrorActionPreference = "Continue"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutDir = Join-Path $ScriptDir "out"
$Pcap = Join-Path $OutDir "nari_net_103_loopback.pcapng"

if (-not $Tshark) {
    $candidates = @(
        "C:\Development\wsbuild-industrial\run\RelWithDebInfo\tshark.exe",
        "C:\Program Files\Wireshark\tshark.exe"
    )
    foreach ($c in $candidates) {
        if (Test-Path $c) { $Tshark = $c; break }
    }
}
if (-not $Dumpcap) {
    $Dumpcap = Join-Path (Split-Path $Tshark -Parent) "dumpcap.exe"
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Remove-Item $Pcap -ErrorAction SilentlyContinue

$iface = "8"
if ($Dumpcap -and (Test-Path $Dumpcap)) {
    $list = & $Dumpcap -D 2>&1 | Out-String
    if ($list -match '(\d+)\.\s+.*Loopback') {
        $iface = $Matches[1]
    }
}

Write-Host "=== NARI network 103 local capture test ==="
Write-Host "PCAP: $Pcap"
Write-Host "Interface: $iface (Npcap loopback)"

if ($Dumpcap -and (Test-Path $Dumpcap)) {
    $capJob = Start-Job -ScriptBlock {
        param($dc, $iface, $out, $dur)
        & $dc -i $iface -f "tcp port 1048 or udp port 1032" -a "duration:$dur" -w $out 2>&1
    } -ArgumentList $Dumpcap, $iface, $Pcap, $DurationSec
    Start-Sleep -Seconds 1
} else {
    Write-Warning "dumpcap not found; skipping capture"
    $capJob = $null
}

$master = Start-Process -FilePath "python" -ArgumentList @(
    (Join-Path $ScriptDir "nari_net_master.py"),
    "--host", $HostAddr
) -PassThru -WindowStyle Hidden

Start-Sleep -Seconds 2

& python (Join-Path $ScriptDir "nari_net_slave.py") --host $HostAddr --addr 3 --session-sec 22 2>&1 | Out-Null
Start-Sleep -Seconds 1
Stop-Process -Id $master.Id -Force -ErrorAction SilentlyContinue

if ($capJob) {
    Receive-Job $capJob -Wait | Out-Null
    Remove-Job $capJob -Force
}

if (-not (Test-Path $Pcap)) {
    Write-Error "No capture file produced. Enable Npcap loopback adapter."
    exit 1
}

Write-Host "`nPCAP size: $((Get-Item $Pcap).Length) bytes"
Write-Host "=== ASDU type counts ==="
& $Tshark -r $Pcap -Y "nari_net_iec103.typeid" -T fields -e nari_net_iec103.typeid 2>$null |
    Group-Object | Sort-Object Name | ForEach-Object { Write-Host ("  ASDU{0}: {1}" -f $_.Name, $_.Count) }

Write-Host "`n=== ASDU24/25/31 (TOO / TOV / FAN / ACC) sample ==="
& $Tshark -r $Pcap -Y "nari_net_iec103.typeid == 24 || nari_net_iec103.typeid == 25 || nari_net_iec103.typeid == 31" `
    -T fields -e frame.number -e nari_net_iec103.typeid -e nari_net_iec103.too -e nari_net_iec103.tov `
    -e nari_net_iec103.fan -e nari_net_iec103.acc 2>$null | Select-Object -First 8

$lines = @(& $Tshark -r $Pcap -Y "nari_net_iec103.typeid" -T fields -e frame.number 2>$null)
Write-Host "`nDecoded ASDU TCP payloads: $($lines.Count)"
$need = @(23, 24, 25, 26, 27, 29, 30, 31)
$missing = @()
foreach ($t in $need) {
    $n = @(& $Tshark -r $Pcap -Y "nari_net_iec103.typeid == $t" -T fields -e frame.number 2>$null).Count
    if ($n -lt 1) { $missing += $t }
}
if ($lines.Count -lt 20 -or $missing.Count -gt 0) {
    Write-Warning ("Expected full wave sequence; missing ASDU types: {0}" -f ($missing -join ", "))
    exit 2
}
Write-Host "Verification OK — open $Pcap in Wireshark, filter: nari_net_iec103"
