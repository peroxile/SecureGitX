#!/usr/bin/env bats

load helpers/helper.bash

setup() {
  setup_repo
}

teardown() {
  teardown_repo
}

@test "warns when git user.name is missing" {
  run bin/securegitx.sh
  [ "$status" -ne 0 ]
  [[ "$output" =~ user.name ]]
}

@test "warns when git user.email is missing" {
  git config user.name "Test User" 
  git config --unset user.email || true

  run ./bin/securegitx.sh


  [ "$status" -ne 0 ]
  [[ "$output" == "Git user.email is not configured" ]]
}

@test "recommends GitHub no-reply email when enforced" {
  git config user.name "Test User"
  git config user.email "me@example.com"

  echo 'ENFORCE_SAFE_EMAIL=true' > .securegitx_config

  run ./bin/securegitx.sh --safe-email


  [[ "$output" =~ "Recommendation: Use GitHub no-reply email" ]]
}

@test "accepts GitHub no-reply email without warning" {
  git config user.name "Test User"
  git config user.email "user@users.noreply.github.com"

  run ./bin/securegitx.sh
  
  [ "$status" -eq 0 ]
  [[ "$output" =~ "Email safety protected" ]]
}