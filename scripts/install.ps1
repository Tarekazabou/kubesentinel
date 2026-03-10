param(
    [Switch]$Force
)

$ErrorActionPreference = "Stop"

Write-Host "==================================" -ForegroundColor Cyan
Write-Host "KubeSentinel Installation Script" -ForegroundColor Cyan
Write-Host "==================================" -ForegroundColor Cyan
Write-Host ""

$gocheck = go version 2>$null
if (-not $gocheck) {
    Write-Host "X Error: Go is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install Go from https://golang.org/dl/" -ForegroundColor Yellow
    exit 1
}

Write-Host "X Found: $gocheck" -ForegroundColor Green

$installDir = "$env:USERPROFILE\AppData\Local\Programs\kubesentinel"
$binPath = "$installDir\bin"
$binaryName = "kubesentinel.exe"
$binaryPath = "$binPath\$binaryName"

Write-Host "Creating installation directory: $binPath" -ForegroundColor Yellow
if (-not (Test-Path $binPath)) {
    New-Item -ItemType Directory -Path $binPath -Force | Out-Null
}

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$projectRoot = Split-Path -Parent $scriptDir

if (-not (Test-Path "$projectRoot\go.mod")) {
    Write-Host "X Error: go.mod not found. Run this script from the project root." -ForegroundColor Red
    exit 1
}

Write-Host "Building KubeSentinel..." -ForegroundColor Yellow
try {
    Push-Location $projectRoot
    go build -o $binaryPath -ldflags "-s -w" .\cmd\main.go
    Pop-Location
    Write-Host "X Build successful" -ForegroundColor Green
} catch {
    Write-Host "X Build failed: $_" -ForegroundColor Red
    exit 1
}

Write-Host "Verifying installation..." -ForegroundColor Yellow
if (Test-Path $binaryPath) {
    Write-Host "X Binary created: $binaryPath" -ForegroundColor Green
} else {
    Write-Host "X Binary not found after build" -ForegroundColor Red
    exit 1
}

$env:PATH = "$binPath;$env:PATH"

$currentPath = [Environment]::GetEnvironmentVariable("PATH", "User")
if ($currentPath -notlike "*$binPath*") {
    Write-Host "Adding to user PATH..." -ForegroundColor Yellow
    $newPath = "$binPath;$currentPath"
    [Environment]::SetEnvironmentVariable("PATH", $newPath, "User")
    Write-Host "X PATH updated for future sessions" -ForegroundColor Green
} else {
    Write-Host "X Already in PATH" -ForegroundColor Green
}

Write-Host "Testing installation..." -ForegroundColor Yellow
$testCmd = & $binaryPath --help 2>&1
if ($LASTEXITCODE -eq 0) {
    Write-Host "X KubeSentinel is ready to use!" -ForegroundColor Green
} else {
    Write-Host "X Installation complete." -ForegroundColor Green
}

Write-Host ""
Write-Host "Installation Summary:" -ForegroundColor Cyan
Write-Host "  Installation Path: $binPath" -ForegroundColor White
Write-Host "  Binary: $binaryPath" -ForegroundColor White
Write-Host ""
Write-Host "To use kubesentinel from anywhere, reopen your PowerShell terminal." -ForegroundColor Yellow
Write-Host "Then run: kubesentinel --help" -ForegroundColor Yellow
