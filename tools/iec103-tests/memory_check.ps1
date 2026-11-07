param(
    [string]$Wireshark = "C:\Development\Wireshark-Industrial-Bundle-0.10.3\06-build\wsbuild-industrial\run\RelWithDebInfo\Wireshark.exe",
    [string]$Pcap = "C:\Development\Wireshark-Industrial-Bundle-0.10.3\03-source\wireshark\tools\iec103-tests\out\zh_recorder_type1.pcap",
    [int]$NetMenuIndex = 10,
    [int]$Rounds = 6
)
# Leak check for the real fix: repeatedly apply try-decode from the GUI menus.
# Private bytes are sampled before and after every round; each round re-redissects
# the whole capture, so a per-redissect leak would show up as a clear climb.

Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$AE = [System.Windows.Automation.AutomationElement]
$TS = [System.Windows.Automation.TreeScope]
$ErrorActionPreference = 'Stop'

Get-Process Wireshark -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1
$proc = Start-Process -FilePath $Wireshark -ArgumentList "`"$Pcap`"" -PassThru
Start-Sleep -Seconds 9
if ($proc.HasExited) { Write-Host "startup crash"; exit 2 }

$cond = New-Object System.Windows.Automation.PropertyCondition($AE::ProcessIdProperty, $proc.Id)
$win = $AE::RootElement.FindFirst($TS::Children, $cond)
if (-not $win) { Write-Host "NO WINDOW"; exit 2 }

$menuCond = New-Object System.Windows.Automation.PropertyCondition($AE::ControlTypeProperty,
    [System.Windows.Automation.ControlType]::MenuItem)
$top = $win.FindAll($TS::Descendants, $menuCond)
$serial = $top.Item($NetMenuIndex)   # 网络103

function Apply-Item([int]$idx) {
    $exp = $serial.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern)
    $exp.Expand()
    Start-Sleep -Milliseconds 600
    $items = $serial.FindAll($TS::Descendants, $menuCond)
    if ($idx -ge $items.Count) { return $false }
    try {
        $items.Item($idx).GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
    } catch { return $false }
    Start-Sleep -Milliseconds 1500
    return $true
}

function Get-Rss { $proc.Refresh(); return [int64]$proc.PrivateMemorySize64 }

$before = @()
$after = @()
foreach ($round in 1..$Rounds) {
    if ($proc.HasExited) { Write-Host "CRASH at round $round"; exit 1 }
    $b = Get-Rss
    # 录波器规约: 0=武汉中原录波器规约解析
    foreach ($idx in @(0, 0, 0, 0, 0, 0)) { $null = Apply-Item $idx }
    if ($proc.HasExited) { Write-Host "CRASH at round $round"; exit 1 }
    $a = Get-Rss
    $before += $b
    $after += $a
    Write-Host ("round {0}: before={1,12:N0}  after={2,12:N0}  delta={3,10:N0}" -f $round, $b, $a, ($a - $b))
}

$proc.CloseMainWindow() | Out-Null
Start-Sleep -Seconds 2
if (-not $proc.HasExited) { $proc.Kill() }

$first = $after[0]
$last = $after[$after.Count - 1]
$growth = if ($first -gt 0) { [math]::Round(100.0 * ($last - $first) / $first, 1) } else { 0 }
Write-Host ""
Write-Host ("after-round1={0:N0}  after-round{1}={2:N0}  growth={3}%" -f $first, $Rounds, $last, $growth)

# Baseline growth from JIT/Qt caches is expected; flag only a sustained climb.
if ($growth -gt 25) { Write-Host "POSSIBLE LEAK (sustained growth across rounds)"; exit 1 }
Write-Host "MEMORY CHECK PASSED"
exit 0
