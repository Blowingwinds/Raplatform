[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$Message = ''
)

$ErrorActionPreference = 'Stop'

function Invoke-Git {
    param(
        [Parameter(Mandatory)]
        [string[]]$Arguments
    )

    & git @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "git $($Arguments -join ' ') failed with exit code $LASTEXITCODE."
    }
}

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw 'Git was not found on PATH.'
}

$startingDirectory = (Get-Location).Path
Push-Location $startingDirectory
try {
    $repositoryRoot = (& git rev-parse --show-toplevel 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($repositoryRoot)) {
        throw 'The current directory is not inside a Git repository.'
    }
    Set-Location -LiteralPath $repositoryRoot

    $branch = (& git symbolic-ref --quiet --short HEAD 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($branch)) {
        throw 'The repository is in detached HEAD state; check out a branch first.'
    }

    $remoteUrl = (& git remote get-url origin 2>$null).Trim()
    if ($LASTEXITCODE -ne 0 -or [string]::IsNullOrWhiteSpace($remoteUrl)) {
        throw 'Remote "origin" is not configured.'
    }

    Write-Host "Repository: $repositoryRoot"
    Write-Host "Branch:     $branch"
    Write-Host "Remote:     $remoteUrl"

    Invoke-Git @('add', '--all')

    & git diff --cached --quiet
    $stagedDiffExitCode = $LASTEXITCODE
    if ($stagedDiffExitCode -eq 1) {
        if ([string]::IsNullOrWhiteSpace($Message)) {
            $Message = "Update project $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        }
        Invoke-Git @('commit', '-m', $Message)
    }
    elseif ($stagedDiffExitCode -ne 0) {
        throw "Unable to inspect staged changes; git diff exited with code $stagedDiffExitCode."
    }
    else {
        Write-Host 'No new file changes to commit.'
    }

    & git ls-remote --exit-code --heads origin $branch *> $null
    $remoteBranchExitCode = $LASTEXITCODE
    if ($remoteBranchExitCode -eq 0) {
        Invoke-Git @('pull', '--rebase', 'origin', $branch)
    }
    elseif ($remoteBranchExitCode -ne 2) {
        throw "Unable to check remote branch; git ls-remote exited with code $remoteBranchExitCode."
    }

    Invoke-Git @('push', '--set-upstream', 'origin', $branch)
    Write-Host "Push completed for origin/$branch."
}
finally {
    Pop-Location
}
