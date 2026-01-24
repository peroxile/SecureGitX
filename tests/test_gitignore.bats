#!/usr/bin/env bats

load helpers/helper.bash

setup() {
  setup_repo
}

teardown() {
  teardown_repo
}

@test ".gitignore is created automatically" {
  run ./bin/securegitx.sh
  [ "$status" -eq 0 ]
  [ -f .gitignore ]
}

@test "python project generates python-specific ignores" {
  touch requirements.txt

  run ./bin/securegitx.sh

  [ "$status" -eq 0 ]
  grep -q "__pycache__/" .gitignore
}

@test "existing .gitignore is respected and config is added" {
  echo "node_modules/" > .gitignore
  run ./bin/securegitx.sh
  [ "$status" -eq 0 ]
  grep -q ".securegitx_config" .gitignore
}
