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
$goCommand = Get-Command go -CommandType Application -ErrorAction Stop | Select-Object -First 1
$goExecutable = $goCommand.Source
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
$hasNativeErrorPreference = Test-Path -LiteralPath 'Variable:PSNativeCommandUseErrorActionPreference'
$previousNativeErrorPreference = $null
if ($hasNativeErrorPreference) {
    $previousNativeErrorPreference = $PSNativeCommandUseErrorActionPreference
}
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
    if ($hasNativeErrorPreference) {
        $PSNativeCommandUseErrorActionPreference = $false
    }
    $commandErrorActionPreference = $ErrorActionPreference
    $nativeExitCode = $null
    try {
        # Windows PowerShell 5.1 can promote native stderr into ErrorRecords.
        # Capture the native status explicitly instead of letting that replace it.
        $ErrorActionPreference = 'Continue'
        & $goExecutable test -tags=operational -count=1 -timeout $timeoutText -run $runPattern -v ./test/operational
        $nativeExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $commandErrorActionPreference
    }
    if ($null -eq $nativeExitCode) {
        throw 'The Go test process did not report a native exit code.'
    }
    $exitCode = [int]$nativeExitCode

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
    try {
        Set-Location -LiteralPath $previousLocation -ErrorAction Stop
    }
    catch {
        Write-Warning "Failed to restore the original working directory: $($_.Exception.Message)"
        $cleanupFailed = $true
    }
    try {
        [Environment]::SetEnvironmentVariable('RECONDUCTOR_E2E_RUN_ID', $previousRunId, 'Process')
        [Environment]::SetEnvironmentVariable('RECONDUCTOR_E2E_ROOT', $previousRoot, 'Process')
    }
    catch {
        Write-Warning "Failed to restore operational E2E environment variables: $($_.Exception.Message)"
        $cleanupFailed = $true
    }
    if ($hasNativeErrorPreference) {
        $PSNativeCommandUseErrorActionPreference = $previousNativeErrorPreference
    }

    $schedulerPidPath = Join-Path $runRoot 'scheduler.pid'
    if (Test-Path -LiteralPath $schedulerPidPath -PathType Leaf) {
        $schedulerRecord = $null
        try {
            $schedulerRecord = Get-Content -LiteralPath $schedulerPidPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
        }
        catch {
            Write-Warning "Refusing scheduler fallback cleanup because its PID identity record is invalid: $($_.Exception.Message)"
            $cleanupFailed = $true
        }
        if ($null -ne $schedulerRecord) {
            $schedulerPid = 0
            $schedulerGeneration = 0
            $schedulerIdentity = [string]$schedulerRecord.identity
            $recordedExecutable = [string]$schedulerRecord.executable
            $recordedStartText = [string]$schedulerRecord.started_at
            $expectedScheduler = [System.IO.Path]::GetFullPath((Join-Path $runRoot 'bin\scheduler.exe'))
            $validRecord = [int]::TryParse([string]$schedulerRecord.pid, [ref]$schedulerPid) -and $schedulerPid -gt 0
            $validRecord = $validRecord -and [int]::TryParse([string]$schedulerRecord.generation, [ref]$schedulerGeneration) -and $schedulerGeneration -gt 0
            $validRecord = $validRecord -and $schedulerIdentity -match '^\d+$'
            try {
                $recordedExecutable = [System.IO.Path]::GetFullPath($recordedExecutable)
                $recordedStart = [DateTimeOffset]::Parse($recordedStartText, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::RoundtripKind).UtcDateTime
            }
            catch {
                $validRecord = $false
            }
            $validRecord = $validRecord -and $recordedExecutable.Equals($expectedScheduler, [System.StringComparison]::OrdinalIgnoreCase)
            if (-not $validRecord) {
                Write-Warning "Refusing scheduler fallback cleanup because its PID identity record is incomplete or outside $expectedScheduler."
                $cleanupFailed = $true
            }
            else {
                $schedulerProcess = Get-Process -Id $schedulerPid -ErrorAction SilentlyContinue
                if ($null -ne $schedulerProcess) {
                    $actualScheduler = $null
                    $actualIdentity = $null
                    $actualStart = $null
                    try {
                        $actualScheduler = [System.IO.Path]::GetFullPath($schedulerProcess.Path)
                        # Accessing Handle pins the verified process object until
                        # after taskkill, so Windows cannot reuse this PID in the
                        # identity-check-to-termination interval.
                        $heldSchedulerHandle = $schedulerProcess.Handle
                        $actualStart = $schedulerProcess.StartTime.ToUniversalTime()
                        $actualIdentity = $actualStart.ToFileTimeUtc().ToString([Globalization.CultureInfo]::InvariantCulture)
                    }
                    catch {
                        $actualScheduler = $null
                        $actualIdentity = $null
                    }
                    if ($null -ne $actualScheduler -and
                        $actualScheduler.Equals($expectedScheduler, [System.StringComparison]::OrdinalIgnoreCase) -and
                        $actualIdentity -eq $schedulerIdentity -and
                        $actualStart.Ticks -eq $recordedStart.Ticks) {
                        & taskkill.exe /PID $schedulerPid /T /F 2>$null | Out-Null
                        [GC]::KeepAlive($schedulerProcess)
                        if ($LASTEXITCODE -ne 0) {
                            Write-Warning "Failed to terminate owned scheduler process tree PID $schedulerPid."
                            $cleanupFailed = $true
                        }
                    }
                    else {
                        Write-Warning "Refusing to terminate PID $schedulerPid because its live executable or creation identity does not match generation $schedulerGeneration."
                        $cleanupFailed = $true
                    }
                }
                else {
                    Write-Warning "Scheduler PID identity record remained for generation $schedulerGeneration, but PID $schedulerPid no longer exists; descendant cleanup cannot be proven."
                    $cleanupFailed = $true
                }
            }
        }
    }

    $containerCleanupIntents = @(
        [PSCustomObject]@{ Name = $postgresName; Path = (Join-Path $runRoot 'postgres.container.intent') },
        [PSCustomObject]@{ Name = $redisName; Path = (Join-Path $runRoot 'redis.container.intent') }
    )
    $pendingContainerIntents = @($containerCleanupIntents | Where-Object { Test-Path -LiteralPath $_.Path -PathType Leaf })
    if ($pendingContainerIntents.Count -gt 0) {
        if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
            Write-Warning 'Docker CLI became unavailable while owned E2E container intents remained.'
            $cleanupFailed = $true
        }
        else {
            foreach ($containerIntent in $pendingContainerIntents) {
                $containerName = $containerIntent.Name
                $ownershipOutput = & docker inspect $containerName 2>&1
                $inspectExit = $LASTEXITCODE
                $inspectText = (@($ownershipOutput) -join [Environment]::NewLine)
                if ($inspectExit -eq 0) {
                    $ownership = $null
                    try {
                        $containerDetails = $inspectText | ConvertFrom-Json
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
                elseif ($inspectText -match '(?i)no such (object|container)') {
                    continue
                }
                else {
                    & docker info 2>$null | Out-Null
                    if ($LASTEXITCODE -ne 0) {
                        Write-Warning "Docker became unavailable while checking E2E container $containerName."
                        $cleanupFailed = $true
                    }
                    else {
                        Write-Warning "Failed to inspect ownership for E2E container $containerName."
                        $cleanupFailed = $true
                    }
                }
            }
        }
    }

    $preserve = $preserveRequested -and ($exitCode -ne 0 -or $cleanupFailed)

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
        if ($exitCode -eq 0) {
            $exitCode = 1
        }
    }
}

exit $exitCode
