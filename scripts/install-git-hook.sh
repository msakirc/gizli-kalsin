#!/usr/bin/env bash
# Install the placeholder-blocking git hooks into one repository.
#   scripts/install-git-hook.sh ~/work/orders-api
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
REPO="${1:?usage: install-git-hook.sh <repo>}"
HOOKS="$(git -C "$REPO" rev-parse --git-path hooks)"
[[ "$HOOKS" = /* ]] || HOOKS="$REPO/$HOOKS"
mkdir -p "$HOOKS"
for h in pre-commit commit-msg; do
  if [[ -e "$HOOKS/$h" && ! -L "$HOOKS/$h" ]]; then
    echo "skip $h: $HOOKS/$h already exists (add a call to $HERE/$h from it)"
  else
    ln -sf "$HERE/$h" "$HOOKS/$h"
    echo "installed $h -> $HOOKS/$h"
  fi
done
