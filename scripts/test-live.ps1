# Build without administrator privileges, then elevate the live test suite once.
[CmdletBinding()]
param(
    # Internal arguments used by the elevated copy of this script.
    [string] $TestBinary,
    [string] $LogPath
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Test-Administrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    try {
        $principal = [Security.Principal.WindowsPrincipal]::new($identity)
        return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    } finally {
        $identity.Dispose()
    }
}

if ($env:OS -ne 'Windows_NT') {
    throw 'This runner is for Windows. On Linux, run the live tests with capture permissions.'
}

if ($TestBinary) {
    if (-not (Test-Administrator)) {
        throw 'The live test worker must run as administrator.'
    }
    if (-not $LogPath) {
        throw 'The live test worker requires a log path.'
    }
    # One elevated parent covers every dumpcap invocation and traffic helper.
    # Serialize captures to avoid interference on the shared loopback adapter.
    & $TestBinary 'captures_' '--ignored' '--test-threads=1' '--nocapture' *> $LogPath
    exit $LASTEXITCODE
}

$workspace = Split-Path -Parent $PSScriptRoot
Push-Location $workspace
try {
    $buildOutput = & cargo test --test live_capture --no-run --message-format=json
    if ($LASTEXITCODE -ne 0) {
        throw 'Failed to build the live tests. No elevation requested.'
    }
    $artifacts = @($buildOutput | ForEach-Object { $_ | ConvertFrom-Json } |
        Where-Object { $_.reason -eq 'compiler-artifact' } |
        Where-Object { $_.target.name -eq 'live_capture' -and $_.executable })
    if ($artifacts.Count -ne 1) {
        throw 'Expected exactly one live_capture test executable.'
    }
    $binary = $artifacts[0].executable
    $log = Join-Path (Split-Path -Parent $binary) 'live-capture-tests.log'
    if (Test-Administrator) {
        & $PSCommandPath -TestBinary $binary -LogPath $log
        exit $LASTEXITCODE
    }

    # EncodedCommand preserves spaces, quotes, and Unicode in all paths.
    $scriptLiteral = $PSCommandPath.Replace("'", "''")
    $binaryLiteral = $binary.Replace("'", "''")
    $logLiteral = $log.Replace("'", "''")
    $workerCommand = "& '$scriptLiteral' -TestBinary '$binaryLiteral' -LogPath '$logLiteral'"
    $encodedCommand = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($workerCommand))
    $shell = (Get-Process -Id $PID).Path
    Write-Host 'Confirm one UAC prompt to run all live capture checks.'
    $worker = Start-Process -FilePath $shell -Verb RunAs -WindowStyle Hidden -Wait -PassThru `
        -ArgumentList @('-NoProfile', '-ExecutionPolicy', 'Bypass', '-EncodedCommand', $encodedCommand)
    if (Test-Path -LiteralPath $log) {
        Get-Content -LiteralPath $log
    }
    Write-Host "Live test log: $log"
    exit $worker.ExitCode
} finally {
    Pop-Location
}
