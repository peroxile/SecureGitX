# tests/helpers/helper.bash

setup() {
  TMP_REPO="$(mktemp -d)"
  cd "$TMP_REPO" || exit 1

  git init -q

  # Hard isolation from user machine
  export GIT_CONFIG_GLOBAL=/dev/null
  export GIT_CONFIG_SYSTEM=/dev/null

  git config --local --unset user.name 2>/dev/null || true
  git config --local --unset user.email 2>/dev/null || true
}

teardown() {
  cd /
  rm -rf "$TMP_REPO"
}
