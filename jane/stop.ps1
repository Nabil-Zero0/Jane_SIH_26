$ErrorActionPreference = "Stop"

$ProjectRoot = $PSScriptRoot
$StateFile = Join-Path $ProjectRoot ".jane-processes.json"

if (Test-Path $StateFile) {
    $json = Get-Content -Raw -LiteralPath $StateFile
    $state = ConvertFrom-Json -InputObject $json
    $services = if ($null -ne $state.services) { @($state.services) } else { @($state) }
    foreach ($service in $services) {
        try {
            & taskkill.exe /PID ([string]$service.pid) /T /F 2>$null | Out-Null
            Write-Host "Stopped $($service.name) (PID $($service.pid))."
        }
        catch {
            Write-Host "$($service.name) (PID $($service.pid)) is not running."
        }
    }
    Remove-Item -LiteralPath $StateFile -Force
}

# Ensure any lingering listeners on Jane's ports are cleanly terminated
foreach ($port in @(4096, 8080, 3000)) {
    $conns = Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue
    if ($conns) {
        foreach ($conn in $conns) {
            try {
                & taskkill.exe /PID ([string]$conn.OwningProcess) /T /F 2>$null | Out-Null
                Write-Host "Killed lingering process $($conn.OwningProcess) on port $port."
            } catch { }
        }
    }
}

Write-Host "Jane services stopped."

