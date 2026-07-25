<#
.SYNOPSIS
    Pushes the AMES (Layer 8) fork to GitHub.

.DESCRIPTION
    Verifies the working tree, runs the test suite, ensures a git repo with a
    commit exists, adds the GitHub remote, and pushes.

    This script never asks for, stores, or transmits your token. Git prompts you
    for credentials directly, so they go from you to git without passing through
    this script.

    BEFORE RUNNING: create an EMPTY repo at https://github.com/new
    Do NOT initialise it with a README, .gitignore, or licence -- an initialised
    repo has a commit this push does not descend from, and the push is rejected.

.PARAMETER GitHubUser
    Your GitHub username. Required.

.PARAMETER RepoName
    Target repository name. Defaults to 'ames'.

.PARAMETER SkipTests
    Skip the pytest run. Not recommended: the whole premise of this layer is
    that a control without a passing test is a hypothesis.

.PARAMETER DryRun
    Do everything except the final push. Run this first.

.EXAMPLE
    .\Push-ToGitHub.ps1 -GitHubUser yourname -DryRun
    .\Push-ToGitHub.ps1 -GitHubUser yourname

.NOTES
    AUTHENTICATION
    GitHub requires a Personal Access Token as the password, not your account
    password. Create one at https://github.com/settings/tokens with 'repo' scope.

    When git prompts:  Username: <your github username>
                       Password: ghp_xxxxxxxxxxxxxxxx
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$GitHubUser,
    [string]$RepoName = 'ames',
    [switch]$SkipTests,
    [switch]$DryRun
)

$ErrorActionPreference = 'Stop'

# PowerShell 7.3+ can turn native-command stderr into a terminating error. git
# and pytest both write ordinary progress there. Exit codes are checked
# explicitly instead.
if (Test-Path variable:PSNativeCommandUseErrorActionPreference) {
    $PSNativeCommandUseErrorActionPreference = $false
}

function Write-Step { param($m) Write-Host "`n=== $m" -ForegroundColor Cyan }
function Write-Ok   { param($m) Write-Host "    [ok] $m" -ForegroundColor Green }
function Write-Warn { param($m) Write-Host "    [!!] $m" -ForegroundColor Yellow }

function Invoke-Git {
    param([string[]]$Arguments, [string]$WorkingDirectory = $PSScriptRoot)
    Push-Location $WorkingDirectory
    try {
        & git @Arguments
        if ($LASTEXITCODE -ne 0) {
            throw "git $($Arguments -join ' ') failed with exit code $LASTEXITCODE"
        }
    }
    finally { Pop-Location }
}


function Invoke-GitCapture {
    <#
        Runs git and returns its combined output plus exit code, WITHOUT ever
        throwing -- for the cases where a nonzero exit is expected information
        rather than a failure (no remote yet, no commit yet, no staged changes).

        PowerShell 5.1 converts a native command's REDIRECTED stderr into a
        terminating NativeCommandError whenever $ErrorActionPreference is
        'Stop'. `git remote get-url origin` errors normally when no remote has
        been added, which is exactly the first-run state, so the preference is
        relaxed for the duration of the call and restored afterwards.
        $PSNativeCommandUseErrorActionPreference does not exist before 7.3 and
        cannot be relied on here.
    #>
    param([string[]]$Arguments, [string]$WorkingDirectory = $PSScriptRoot)

    $previous = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    Push-Location $WorkingDirectory
    try {
        $output = (& git @Arguments 2>&1 | Out-String)
        return [pscustomobject]@{
            Output   = $output.Trim()
            ExitCode = $LASTEXITCODE
        }
    }
    finally {
        Pop-Location
        $ErrorActionPreference = $previous
    }
}

$root = $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }

$CommitMessage = @'
AMES-V1: tamper-evident agent action ledger (Layer 8)

Generalises KAYSentinel's EMES from EVM state transitions to agent actions.
An EVM call frame becomes an OS process, so Gate 1's frame-balance invariant
carries over directly as process lineage verification.

- Canonical 41-byte event header, no JSON on the commitment path
- Domain-separated BLAKE3 (leaf/node separation prevents CVE-2012-2459 class
  second-preimage attacks; odd levels promote rather than duplicate)
- Hash-linked blocks with merkle roots and inclusion proofs
- Gate 1 lineage balance: hiding an action requires hiding a consistent set of
  events, so suppressing one spawn leaves a detectable orphan
- External checkpoints for tail-truncation resistance
- 37 tests, all adversarial: content edit, reorder, splice, internally-consistent
  block forgery, count lies, truncation, checkpoint forgery, fork, lineage
  suppression, reserved-bit smuggling
- Pinned conformance vectors for cross-language validation

Documents two real limits rather than hiding them: truncation is undetectable
without an external checkpoint, and a compromised producer can omit events.
'@

# ---------------------------------------------------------------------------
# Preflight
# ---------------------------------------------------------------------------

Write-Step "Preflight"

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    throw "git is not on PATH. Install from https://git-scm.com/download/win"
}
Write-Ok "git $((git --version) -replace 'git version ','')"
Write-Ok "source: $root"

$required = @(
    'ames\__init__.py', 'ames\events.py', 'ames\canonical.py',
    'ames\commit.py', 'ames\ledger.py', 'ames\gate1.py',
    'tests\test_tamper.py', 'tests\test_conformance.py',
    'vectors\ames_v1_conformance.json',
    'docs\ames_specification.md', 'README.md', 'LICENSE', 'requirements.txt'
)
$missing = @($required | Where-Object { -not (Test-Path (Join-Path $root $_)) })
if ($missing.Count -gt 0) {
    throw "Missing required files:`n    - " + ($missing -join "`n    - ")
}
Write-Ok "all $($required.Count) required files present"

# ---------------------------------------------------------------------------
# Tests -- do not push a ledger whose tamper detection is unproven
# ---------------------------------------------------------------------------

if ($SkipTests) {
    Write-Warn "skipping tests (-SkipTests)"
}
else {
    Write-Step "Test suite"
    $python = $null
    foreach ($candidate in @('python', 'python3', 'py')) {
        if (Get-Command $candidate -ErrorAction SilentlyContinue) { $python = $candidate; break }
    }

    if (-not $python) {
        Write-Warn "no python on PATH - cannot verify. Re-run with -SkipTests to push anyway."
        throw "Python not found; refusing to push unverified."
    }

    Push-Location $root
    try {
        & $python -m pytest tests/ -q
        $testExit = $LASTEXITCODE
    }
    finally { Pop-Location }

    if ($testExit -ne 0) {
        throw "Tests failed (exit $testExit). Not pushing. If dependencies are missing: pip install -r requirements.txt"
    }
    Write-Ok "tests passed"
}

# ---------------------------------------------------------------------------
# Ensure a repo with a commit exists
# ---------------------------------------------------------------------------

Write-Step "Repository"

if (-not (Test-Path (Join-Path $root '.git'))) {
    Write-Warn "no .git found - initialising"
    Invoke-Git @('init', '--quiet')
    Invoke-Git @('symbolic-ref', 'HEAD', 'refs/heads/main')
    Write-Ok "initialised on main"
}

$hasCommit = (Invoke-GitCapture @('rev-parse', '--verify', 'HEAD') -WorkingDirectory $root).ExitCode -eq 0

Invoke-Git @('add', '-A')

# --quiet exits 1 when staged differences exist.
$hasStaged = (Invoke-GitCapture @('diff', '--cached', '--quiet') -WorkingDirectory $root).ExitCode -ne 0

if (-not $hasCommit) {
    $msgFile = Join-Path $env:TEMP "ames-commit-$(Get-Random).txt"
    [System.IO.File]::WriteAllText($msgFile, $CommitMessage, (New-Object System.Text.UTF8Encoding($false)))
    Invoke-Git @('-c', 'user.email=onlyairdropshere@gmail.com', '-c', 'user.name=Sahek',
                 'commit', '--quiet', '-F', $msgFile)
    Remove-Item $msgFile -ErrorAction SilentlyContinue
    Write-Ok "created initial commit"
}
elseif ($hasStaged) {
    Invoke-Git @('-c', 'user.email=onlyairdropshere@gmail.com', '-c', 'user.name=Sahek',
                 'commit', '--quiet', '-m', 'L5: behavioural fingerprinting (frozen host-observed capability-stream baseline; 24 tests, 222 total)')
    Write-Ok "committed local changes"
}
else {
    Write-Ok "working tree clean, commit already present"
}

# Normalise the branch name; GitHub defaults to main.
Invoke-Git @('branch', '-M', 'main')

$fileCount = @((Invoke-GitCapture @('ls-files') -WorkingDirectory $root).Output -split "`n" |
                Where-Object { $_.Trim() }).Count
$headLine  = (Invoke-GitCapture @('log', '--oneline', '-1') -WorkingDirectory $root).Output
Write-Ok "$fileCount tracked files | HEAD: $headLine"

# ---------------------------------------------------------------------------
# Remote
# ---------------------------------------------------------------------------

Write-Step "Remote"

$url = "https://github.com/$GitHubUser/$RepoName.git"

$originLookup = Invoke-GitCapture @('remote', 'get-url', 'origin') -WorkingDirectory $root
$hasOrigin = ($originLookup.ExitCode -eq 0)
$existing  = $originLookup.Output

if ($hasOrigin) {
    if ($existing.Trim() -ne $url) {
        Write-Warn "origin currently points at $($existing.Trim()) - repointing"
        Invoke-Git @('remote', 'set-url', 'origin', $url)
    }
    Write-Ok "origin -> $url"
}
else {
    Invoke-Git @('remote', 'add', 'origin', $url)
    Write-Ok "added origin -> $url"
}

# Confirm the target exists and is empty before attempting a push.
$lsRemote   = Invoke-GitCapture @('ls-remote', '--heads', 'origin') -WorkingDirectory $root
$reachable  = ($lsRemote.ExitCode -eq 0)
$remoteRefs = $lsRemote.Output

if (-not $reachable) {
    Write-Warn "cannot reach $url"
    Write-Warn "create an EMPTY repo first at https://github.com/new (no README/licence)"
    throw "Remote not reachable or does not exist."
}
if ($remoteRefs.Trim()) {
    Write-Warn "remote already has branches:"
    $remoteRefs.Trim().Split("`n") | ForEach-Object { Write-Host "      $_" -ForegroundColor DarkGray }
    Write-Warn "if this repo was initialised with a README, the push will be rejected."
    Write-Warn "either delete and recreate it empty, or push with --force if you are certain."
}
else {
    Write-Ok "remote exists and is empty"
}

# ---------------------------------------------------------------------------
# Push
# ---------------------------------------------------------------------------

Write-Step "Push"

if ($DryRun) {
    Write-Warn "DRY RUN - not pushing."
    Write-Host "    Would run: git push -u origin main" -ForegroundColor DarkGray
    Write-Host "    Inspect with: git -C `"$root`" show --stat" -ForegroundColor DarkGray
}
else {
    Write-Host "    pushing (git may prompt for username + Personal Access Token)..." -ForegroundColor Yellow
    Invoke-Git @('push', '-u', 'origin', 'main')
    Write-Ok "PUSHED to https://github.com/$GitHubUser/$RepoName"
    Write-Host "`nDone. Verify at https://github.com/$GitHubUser/$RepoName" -ForegroundColor Green
}
