$ErrorActionPreference = 'Stop'

if (-not (Get-Command git-secrets -ErrorAction SilentlyContinue)) {
    Write-Error "git-secrets is not installed or not on PATH. Install it first, then rerun this script."
}

$repoRoot = (git rev-parse --show-toplevel).Trim()
Set-Location $repoRoot

git secrets --install -f
git secrets --register-aws

git secrets --add --literal '-----BEGIN OPENSSH PRIVATE KEY-----'
git secrets --add --literal '-----BEGIN PRIVATE KEY-----'
git secrets --add --literal '-----BEGIN RSA PRIVATE KEY-----'
git secrets --add '(api[_-]?key|token|secret|client[_-]?secret|password|passwd|pwd|session[_-]?secret)[[:space:]]*[:=][[:space:]]*["''`][^"''`[:space:]]{8,}["''`]'
git secrets --add 'gh[pousr]_[A-Za-z0-9_]{20,255}'
git secrets --add 'github_pat_[A-Za-z0-9_]{20,255}'
git secrets --add 'xox[baprs]-[A-Za-z0-9-]{10,200}'

Write-Host "git-secrets hooks installed for $repoRoot"
