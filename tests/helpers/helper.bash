#!/usr/bin/env bash

# Create a temporary Git repo for isolated testing
create_temp_repo() {
  # Use BATS_TEST_TMPDIR if available, else mktemp
  TEST_REPO_DIR="${BATS_TEST_TMPDIR:-$(mktemp -d -t securegitx-test-XXXXXX)}"
  cd "$TEST_REPO_DIR" || exit 1
  git init -q >/dev/null 2>&1
  # Copy SecureGitX script/tool into temp repo for testing
  cp -r "${BATS_TEST_DIRNAME}/../bin" "${BATS_TEST_DIRNAME}/../wrappers" "$TEST_REPO_DIR"/
  # Optional: Pre-configure safe defaults if needed
}

# Cleanup after each test
teardown_repo() {
  # Return to original dir (safe even if cd fails)
  cd "${BATS_TEST_DIRNAME}/.." || true
  # Optional: rm -rf "$TEST_REPO_DIR" if not using BATS_TMPDIR (Bats cleans it auto)
}