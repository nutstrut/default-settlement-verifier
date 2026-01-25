Add-Type -AssemblyName System.Windows.Forms

# =========================
# Verifier Monitoring Script
# =========================

$verifierUrl = "http://localhost:3000/health"
$trustLog = ".\trust-log.jsonl"

# Track previous log length
$prevCount = 0

while ($true) {
try {
# Health check
$response = Invoke-WebRequest -Uri $verifierUrl -UseBasicParsing -TimeoutSec 5
$json = $response.Content | ConvertFrom-Json

if ($json.status -ne "ok") {
[System.Windows.Forms.MessageBox]::Show("Verifier health check failed!", "ALERT")
}

# Check for new trust log entries
if (Test-Path $trustLog) {
$lines = Get-Content $trustLog
$newCount = $lines.Count

if ($newCount -gt $prevCount) {
$newEntries = $lines[$prevCount..($newCount - 1)]
foreach ($entry in $newEntries) {
$obj = $entry | ConvertFrom-Json
if ($obj.verdict -eq "FAIL") {
[System.Windows.Forms.MessageBox]::Show(
"FAIL detected: Task $($obj.task_id) | Reason $($obj.reason_code)",
"Verifier Alert"
)
}
}
$prevCount = $newCount
}
}

} catch {
# If Verifier is down
[System.Windows.Forms.MessageBox]::Show(
"Verifier is not responding!",
"CRITICAL ALERT"
)
}

Start-Sleep -Seconds 10
}