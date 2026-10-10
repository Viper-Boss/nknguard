$ErrorActionPreference = 'Stop'
# Run only in an isolated runner; no VPN or administrator action is requested.
$binary = (Resolve-Path 'NKNGuard-Windows.exe').Path
$process = Start-Process $binary -PassThru -WindowStyle Hidden
try {
    $deadline = (Get-Date).AddSeconds(30)
    do {
        Start-Sleep -Milliseconds 500
        $process.Refresh()
        if ($process.HasExited) { throw "Client exited during native GUI startup: $($process.ExitCode)" }
    } while ($process.MainWindowHandle -eq 0 -and (Get-Date) -lt $deadline)
    if ($process.MainWindowHandle -eq 0 -or $process.MainWindowTitle -ne 'NKNGuard') { throw 'Native NKNGuard window did not open' }
    Start-Sleep -Seconds 3
    $process.Refresh()
    if ($process.HasExited) { throw 'Native GUI did not remain responsive' }
    Write-Output 'Native Windows client window opened and remained running.'
} finally {
    if (!$process.HasExited) { Stop-Process -Id $process.Id -Force }
}
