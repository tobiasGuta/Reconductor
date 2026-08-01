[CmdletBinding()]
param(
    [TimeSpan]$Timeout = [TimeSpan]::FromMinutes(8),
    [ValidateSet('Approval', 'Recovery', 'All')]
    [string]$Suite = 'Approval'
)

$ErrorActionPreference = 'Stop'
if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
    throw 'This wrapper supports Windows PowerShell 5.1 and PowerShell 7 on Windows.'
}
$scriptRoot = Split-Path -Parent $PSCommandPath
$repositoryRoot = [System.IO.Path]::GetFullPath((Join-Path $scriptRoot '..'))
$goMod = Join-Path $repositoryRoot 'go.mod'
if (-not (Test-Path -LiteralPath $goMod -PathType Leaf)) {
    throw "Reconductor go.mod was not found beneath $repositoryRoot"
}
$moduleLine = Get-Content -LiteralPath $goMod -TotalCount 1
if ($moduleLine -ne 'module github.com/tobiasGuta/Reconductor') {
    throw "Refusing to run outside the Reconductor repository: $repositoryRoot"
}
if ($Timeout -le [TimeSpan]::Zero) {
    throw 'Timeout must be positive.'
}
$runPattern = switch ($Suite) {
    'Approval' { '^TestApprovalLifecycle$' }
    'Recovery' { '^TestRecoveryLifecycle$' }
    'All' { '^(TestApprovalLifecycle|TestRecoveryLifecycle)$' }
    default { throw "Unsupported operational suite: $Suite" }
}

$runId = [Guid]::NewGuid().ToString('N').Substring(0, 16).ToLowerInvariant()
$temporaryBase = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
$runRoot = [System.IO.Path]::GetFullPath((Join-Path $temporaryBase "reconductor-operational-e2e-$runId"))
if (-not $runRoot.StartsWith($temporaryBase, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Generated operational root escapes the system temporary directory: $runRoot"
}

$postgresName = "reconductor-e2e-pg-$runId"
$redisName = "reconductor-e2e-redis-$runId"
$previousLocation = Get-Location
$previousRunId = [Environment]::GetEnvironmentVariable('RECONDUCTOR_E2E_RUN_ID', 'Process')
$previousRoot = [Environment]::GetEnvironmentVariable('RECONDUCTOR_E2E_ROOT', 'Process')
$exitCode = 1
$preserve = $false
$preserveRequested = $false
$cleanupFailed = $false

try {
    New-Item -ItemType Directory -Path $runRoot -Force | Out-Null
    [Environment]::SetEnvironmentVariable('RECONDUCTOR_E2E_RUN_ID', $runId, 'Process')
    [Environment]::SetEnvironmentVariable('RECONDUCTOR_E2E_ROOT', $runRoot, 'Process')
    Set-Location -LiteralPath $repositoryRoot

    $timeoutText = '{0}s' -f [Math]::Ceiling($Timeout.TotalSeconds)
    & go test -tags=operational -count=1 -timeout $timeoutText -run $runPattern -v ./test/operational
    $exitCode = $LASTEXITCODE

    $preserveValue = [Environment]::GetEnvironmentVariable('RECONDUCTOR_E2E_PRESERVE_FAILURE', 'Process')
    $preserveRequested = $preserveValue -match '^(?i:true|1|yes)$'
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    $exitCode = 1
    $preserveValue = [Environment]::GetEnvironmentVariable('RECONDUCTOR_E2E_PRESERVE_FAILURE', 'Process')
    $preserveRequested = $preserveValue -match '^(?i:true|1|yes)$'
}
finally {
    # Windows PowerShell 5.1 promotes native stderr to an ErrorRecord when the
    # script preference is Stop. Fallback cleanup evaluates native exit codes
    # explicitly, so use Continue here and keep filesystem deletion terminating.
    $ErrorActionPreference = 'Continue'
    $schedulerPidPath = Join-Path $runRoot 'scheduler.pid'
    if (Test-Path -LiteralPath $schedulerPidPath -PathType Leaf) {
        $schedulerPidText = (Get-Content -LiteralPath $schedulerPidPath -Raw).Trim()
        $schedulerPid = 0
        if ([int]::TryParse($schedulerPidText, [ref]$schedulerPid) -and $schedulerPid -gt 0) {
            $schedulerProcess = Get-Process -Id $schedulerPid -ErrorAction SilentlyContinue
            if ($null -ne $schedulerProcess) {
                $expectedScheduler = [System.IO.Path]::GetFullPath((Join-Path $runRoot 'bin\scheduler.exe'))
                $actualScheduler = $null
                try {
                    $actualScheduler = [System.IO.Path]::GetFullPath($schedulerProcess.Path)
                }
                catch {
                    $actualScheduler = $null
                }
                if ($null -ne $actualScheduler -and $actualScheduler.Equals($expectedScheduler, [System.StringComparison]::OrdinalIgnoreCase)) {
                    & taskkill.exe /PID $schedulerPid /T /F 2>$null | Out-Null
                    if ($LASTEXITCODE -ne 0 -and $null -ne (Get-Process -Id $schedulerPid -ErrorAction SilentlyContinue)) {
                        Write-Warning "Failed to terminate owned scheduler process tree PID $schedulerPid."
                        $cleanupFailed = $true
                    }
                }
                else {
                    Write-Warning "Refusing to terminate PID $schedulerPid because its executable is not $expectedScheduler."
                    $cleanupFailed = $true
                }
            }
        }
    }

    if (Get-Command docker -ErrorAction SilentlyContinue) {
        $containerCleanupIntents = @(
            [PSCustomObject]@{ Name = $postgresName; Path = (Join-Path $runRoot 'postgres.container.intent') },
            [PSCustomObject]@{ Name = $redisName; Path = (Join-Path $runRoot 'redis.container.intent') }
        )
        foreach ($containerIntent in $containerCleanupIntents) {
            if (-not (Test-Path -LiteralPath $containerIntent.Path -PathType Leaf)) {
                continue
            }
            $containerName = $containerIntent.Name
            $ownershipOutput = & docker inspect $containerName 2>$null
            $inspectExit = $LASTEXITCODE
            if ($inspectExit -eq 0) {
                $ownership = $null
                try {
                    $containerDetails = (@($ownershipOutput) -join [Environment]::NewLine) | ConvertFrom-Json
                    $labels = @($containerDetails)[0].Config.Labels
                    $runLabel = $labels.PSObject.Properties['reconductor.operational-e2e.run'].Value
                    $e2eLabel = $labels.PSObject.Properties['reconductor.operational-e2e'].Value
                    $ownership = "$runLabel|$e2eLabel"
                }
                catch {
                    $ownership = $null
                }
                if ($ownership -eq "$runId|true") {
                    & docker rm -f $containerName 2>$null | Out-Null
                    if ($LASTEXITCODE -ne 0) {
                        Write-Warning "Failed to remove owned E2E container $containerName."
                        $cleanupFailed = $true
                    }
                }
                else {
                    Write-Warning "Refusing to remove container $containerName with ownership labels '$ownership'."
                    $cleanupFailed = $true
                }
            }
            else {
                & docker info 2>$null | Out-Null
                if ($LASTEXITCODE -ne 0) {
                    Write-Warning "Docker became unavailable while checking E2E container $containerName."
                    $cleanupFailed = $true
                }
            }
        }
    }

    $preserve = $preserveRequested -and ($exitCode -ne 0 -or $cleanupFailed)
    Set-Location -LiteralPath $previousLocation
    [Environment]::SetEnvironmentVariable('RECONDUCTOR_E2E_RUN_ID', $previousRunId, 'Process')
    [Environment]::SetEnvironmentVariable('RECONDUCTOR_E2E_ROOT', $previousRoot, 'Process')

    if ($preserve) {
        Write-Warning "Operational E2E diagnostics preserved at $runRoot"
    }
    elseif (Test-Path -LiteralPath $runRoot) {
        $resolvedRoot = [System.IO.Path]::GetFullPath($runRoot)
        $requiredPrefix = [System.IO.Path]::GetFullPath((Join-Path $temporaryBase 'reconductor-operational-e2e-'))
        if (-not $resolvedRoot.StartsWith($requiredPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "Refusing fallback cleanup outside the generated operational root: $resolvedRoot"
        }
        try {
            Remove-Item -LiteralPath $resolvedRoot -Recurse -Force -ErrorAction Stop
        }
        catch {
            Write-Warning "Failed to remove operational E2E root $resolvedRoot`: $($_.Exception.Message)"
            $cleanupFailed = $true
        }
    }
    if ($cleanupFailed) {
        $exitCode = 1
    }
}

exit $exitCode
