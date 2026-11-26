param([string]$LabBindIp)

$ErrorActionPreference = 'Stop'
$repo = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
if (-not $LabBindIp) {
    $LabBindIp = (Get-NetIPAddress -InterfaceAlias 'VMware Network Adapter VMnet8' -AddressFamily IPv4 -ErrorAction SilentlyContinue | Select-Object -First 1 -ExpandProperty IPAddress)
}
if (-not $LabBindIp) {
    throw 'Pass -LabBindIp with the Windows IP on the network shared with Kali.'
}
$env:LAB_BIND_IP = $LabBindIp
$stage = Join-Path $repo ('target\lab-web-' + [guid]::NewGuid().ToString('N'))
$targetRoot = [System.IO.Path]::GetFullPath((Join-Path $repo 'target')) + [System.IO.Path]::DirectorySeparatorChar
if (-not [System.IO.Path]::GetFullPath($stage).StartsWith($targetRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw 'Build staging path is outside the workspace target directory.'
}

Push-Location $repo
try {
    & (Join-Path $repo 'scripts\build-wasm.cmd')
    if ($LASTEXITCODE -ne 0) { throw 'Rust WebAssembly build failed.' }
    New-Item -ItemType Directory -Path $stage -Force | Out-Null
    Get-ChildItem (Join-Path $repo 'web') -Force | Where-Object { $_.Name -notin @('node_modules', 'dist') } | Copy-Item -Destination $stage -Recurse -Force
    Push-Location $stage
    try {
        npm ci
        if ($LASTEXITCODE -ne 0) { throw 'Frontend dependency install failed.' }
        npm run build
        if ($LASTEXITCODE -ne 0) { throw 'Frontend build failed.' }
    } finally { Pop-Location }
    Copy-Item -Path (Join-Path $stage 'dist\*') -Destination (Join-Path $repo 'web\dist') -Recurse -Force
    docker compose up -d --build
    if ($LASTEXITCODE -ne 0) { throw 'Docker lab startup failed.' }
    Write-Host "Lab target: http://${LabBindIp}:8080/"
    Write-Host 'Monitor: http://localhost:3000/monitor'
    Start-Process 'http://localhost:3000/monitor'
} finally {
    Pop-Location
    if (Test-Path -LiteralPath $stage) { Remove-Item -LiteralPath $stage -Recurse -Force }
}
