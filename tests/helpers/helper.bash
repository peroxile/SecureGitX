#!/usr/bin/env bash

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"

setup_repo() {
  TMP_REPO="$(mktemp -d)"
  cd "$TMP_REPO" || exit 1

  git init >/dev/null 2>&1

  mkdir -p wrappers bin

  cp "$PROJECT_ROOT/wrappers/securegitx_wrapper.py" wrappers/
  cp "$PROJECT_ROOT/bin/securegitx.sh" bin/
  chmod +x bin/securegitx.sh

  git config --local --unset user.name 2>/dev/null || true
  git config --local --unset user.email 2>/dev/null || true

}

teardown_repo() {
  cd "$PROJECT_ROOT" || exit 1
  rm -rf "$TMP_REPO"
}
