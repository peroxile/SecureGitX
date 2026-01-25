#!/usr/bin/env bats

load helpers/helper.bash

setup() {
  setup_repo
  # Default safe identity for most tests
  git config --local user.name "Test User"
  git config --local user.email "test@users.noreply.github.com"
}

teardown() {
  teardown_repo
}

@test "fails when git user.name is missing" {
  git config --local user.name ""
  run ./bin/securegitx.sh

  [[ "$status" -ne 0 ]]
  [[ "$output" =~ "user.name is not configured" ]]
}

@test "fails when git user.email is missing" {
  git config --local user.email ""
  run ./bin/securegitx.sh

  [[ "$status" -ne 0 ]]
  [[ "$output" =~ "Git user.email is not configured" ]]
}

@test "accepts GitHub no-reply email without warning" {
  git config --local user.email "user@users.noreply.github.com"
  run ./bin/securegitx.sh

  [[ "$status" -eq 0 ]]
  [[ "$output" =~ "Email safety protected" ]]
}