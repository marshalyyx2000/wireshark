param(
    [string]$Wireshark = "C:\Development\Wireshark-Industrial-Bundle-0.10.3\06-build\wsbuild-industrial\run\RelWithDebInfo\Wireshark.exe",
    [string]$Pcap = "C:\Development\Wireshark-Industrial-Bundle-0.10.3\03-source\wireshark\tools\iec103-tests\out\zh_recorder_type1.pcap",
    [int]$NetMenuIndex = 10,
    [int]$Rounds = 3
)
Add-Type -AssemblyName UIAutomationClient
Add-Type -AssemblyName UIAutomationTypes
$AE = [System.Windows.Automation.AutomationElement]
$TS = [System.Windows.Automation.TreeScope]
$ErrorActionPreference = 'Stop'

Get-Process Wireshark -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1
$proc = Start-Process -FilePath $Wireshark -ArgumentList "`"$Pcap`"" -PassThru
Start-Sleep -Seconds 9
$cond = New-Object System.Windows.Automation.PropertyCondition($AE::ProcessIdProperty, $proc.Id)
$win = $AE::RootElement.FindFirst($TS::Children, $cond)
if (-not $win) { Write-Host "NO WINDOW"; exit 2 }

$menuCond = New-Object System.Windows.Automation.PropertyCondition($AE::ControlTypeProperty,
    [System.Windows.Automation.ControlType]::MenuItem)
$top = $win.FindAll($TS::Descendants, $menuCond)
Write-Host "top menus: $($top.Count)  using index $NetMenuIndex"
$serial = $top.Item($NetMenuIndex)
Write-Host ("network-103 menu name='{0}'" -f $serial.Current.Name)

function Open-And-Click([int]$index) {
    $exp = $serial.GetCurrentPattern([System.Windows.Automation.ExpandCollapsePattern]::Pattern)
    $exp.Expand()
    Start-Sleep -Milliseconds 800
    $items = $serial.FindAll($TS::Descendants, $menuCond)
    $ok = $false
    if ($index -lt $items.Count) {
        $leaf = $items.Item($index)
        Write-Host ("    click item[{0}] '{1}'" -f $index, $leaf.Current.Name)
        try {
            $leaf.GetCurrentPattern([System.Windows.Automation.InvokePattern]::Pattern).Invoke()
            $ok = $true
        } catch {
            Write-Host "    invoke failed: $($_.Exception.Message)"
        }
    } else {
        Write-Host "    item index $index out of range ($($items.Count))"
    }
    Start-Sleep -Milliseconds 1200
    return $ok
}

# 0=解析 1=导出 (order follows the menuRecorder addaction list)
$plan = @(0, 0, 0, 0)
$fail = 0
for ($r = 1; $r -le $Rounds; $r++) {
    foreach ($idx in $plan) {
        if ($proc.HasExited) { Write-Host "CRASH exit=$($proc.ExitCode)"; exit 1 }
        $ok = Open-And-Click $idx
        if (-not $ok) { $fail++ }
        if ($proc.HasExited) { Write-Host "CRASH exit=$($proc.ExitCode)"; exit 1 }
        Write-Host ("  round {0} item {1} alive=True" -f $r, $idx)
    }
}
Write-Host "still alive after $Rounds rounds"
$proc.CloseMainWindow() | Out-Null
Start-Sleep -Seconds 2
if (-not $proc.HasExited) { $proc.Kill() }
if ($fail -gt 0) { Write-Host "CLICK FAILURES: $fail"; exit 3 }
Write-Host "GUI CLICK TEST PASSED"
