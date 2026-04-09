#!/usr/bin/env bash

set -euo pipefail

if ! command -v git-secrets >/dev/null 2>&1; then
  echo "git-secrets is not installed or not on PATH." >&2
  echo "Install it first, then rerun this script." >&2
  exit 1
fi

repo_root="$(git rev-parse --show-toplevel)"
cd "$repo_root"

git secrets --install -f
git secrets --register-aws

git secrets --add --literal '-----BEGIN OPENSSH PRIVATE KEY-----'
git secrets --add --literal '-----BEGIN PRIVATE KEY-----'
git secrets --add --literal '-----BEGIN RSA PRIVATE KEY-----'
git secrets --add '(api[_-]?key|token|secret|client[_-]?secret|password|passwd|pwd|session[_-]?secret)[[:space:]]*[:=][[:space:]]*['"'"'`][^'"'"'`[:space:]]{8,}['"'"'`]'
git secrets --add 'gh[pousr]_[A-Za-z0-9_]{20,255}'
git secrets --add 'github_pat_[A-Za-z0-9_]{20,255}'
git secrets --add 'xox[baprs]-[A-Za-z0-9-]{10,200}'

echo "git-secrets hooks installed for $repo_root"
