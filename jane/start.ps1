$ErrorActionPreference = "Stop"

$ProjectRoot = $PSScriptRoot
$WorkspaceRoot = Split-Path -Parent $ProjectRoot
$FrontendRoot = Join-Path $ProjectRoot "frontend"
$LogRoot = Join-Path $ProjectRoot "data\logs\services"
$StateFile = Join-Path $ProjectRoot ".jane-processes.json"

New-Item -ItemType Directory -Force -Path $LogRoot | Out-Null

foreach ($port in @(4096, 8080, 3000)) {
    $listener = Get-NetTCPConnection -State Listen -LocalPort $port -ErrorAction SilentlyContinue
    if ($listener) {
        throw "Port $port is already in use by PID $($listener[0].OwningProcess)."
    }
}

if (Test-Path $StateFile) {
    $state = ConvertFrom-Json -InputObject (Get-Content -Raw -LiteralPath $StateFile)
    $existing = if ($null -ne $state.services) { @($state.services) } else { @($state) }
    $alive = @($existing | Where-Object {
        try { Get-Process -Id ([int]$_.pid) -ErrorAction Stop | Out-Null; $true }
        catch { $false }
    })
    if ($alive.Count -gt 0) {
        throw "Jane services already running. Use .\stop.ps1 first."
    }
    Remove-Item -LiteralPath $StateFile -Force
}

function Start-JaneService {
    param(
        [string]$Name,
        [string]$FilePath,
        [string[]]$ArgumentList,
        [string]$WorkingDirectory
    )

    $safeName = $Name.ToLowerInvariant()
    $stdout = Join-Path $LogRoot "$safeName.out.log"
    $stderr = Join-Path $LogRoot "$safeName.err.log"

    $process = Start-Process -FilePath $FilePath -ArgumentList $ArgumentList -WorkingDirectory $WorkingDirectory -RedirectStandardOutput $stdout -RedirectStandardError $stderr -PassThru

    return [PSCustomObject]@{
        name = $Name
        pid = $process.Id
        cwd = $WorkingDirectory
        command = "$FilePath $($ArgumentList -join ' ')"
        stdout = $stdout
        stderr = $stderr
    }
}

$opencode = Get-Command opencode.cmd -ErrorAction SilentlyContinue
if (-not $opencode) { throw "opencode.cmd not found on PATH." }

$python = Get-Command python.exe -ErrorAction SilentlyContinue
if (-not $python) { throw "python.exe not found on PATH." }

$npm = Get-Command npm.cmd -ErrorAction SilentlyContinue
if (-not $npm) { throw "npm.cmd not found on PATH." }

$services = @()
try {
    $services += Start-JaneService `
        -Name "opencode" `
        -FilePath $opencode.Source `
        -ArgumentList @("serve", "--hostname", "127.0.0.1", "--port", "4096") `
        -WorkingDirectory $ProjectRoot

    $services += Start-JaneService `
        -Name "backend" `
        -FilePath $python.Source `
        -ArgumentList @("-m", "jane.web.server", "--port", "8080") `
        -WorkingDirectory $WorkspaceRoot

    $services += Start-JaneService `
        -Name "frontend" `
        -FilePath $npm.Source `
        -ArgumentList @("run", "dev") `
        -WorkingDirectory $FrontendRoot

    @{ services = $services } | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $StateFile -Encoding UTF8

    Write-Host "Jane services started."
    Write-Host "OpenCode: http://127.0.0.1:4096"
    Write-Host "Backend:  http://127.0.0.1:8080"
    Write-Host "Frontend: http://localhost:3000"
    Write-Host "Logs:     $LogRoot"
}
catch {
    foreach ($service in $services) {
        try { & taskkill.exe /PID ([string]$service.pid) /T /F 2>$null | Out-Null } catch { }
    }
    throw
}
