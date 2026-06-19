param(
    [string] $Config = "examples/privacy-proxy.toml",
    [string] $Input = "examples/logs.jsonl",
    [string] $Output = "clean.jsonl"
)

cargo build --release -p privacy-proxy
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

$binary = Join-Path (Get-Location) "target\release\privacy-proxy.exe"
$arguments = @("--config", $Config, "redact", "--input", $Input, "--output", $Output)
$process = Start-Process -FilePath $binary -ArgumentList $arguments -PassThru -WindowStyle Hidden

while (-not $process.HasExited) {
    Start-Sleep -Milliseconds 50
    $process.Refresh()
}

$process.Refresh()
$peakMiB = [Math]::Round($process.PeakWorkingSet64 / 1MB, 2)
Write-Output "peak_working_set_mib=$peakMiB"
exit $process.ExitCode
