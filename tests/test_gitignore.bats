#!/usr/bin/env bats

load helpers/helper.bash

setup() {
  setup_repo
  git config user.name "Test User"
  git config user.email "test@users.noreply.github.com"
}

teardown() {
  teardown_repo
}

@test "creates default config and .gitignore automatically" {
  run ./bin/securegitx.sh

  [ "$status" -eq 0 ]
  [ -f .securegitx_config ]
  [ -f .gitignore ]
  grep -q ".securegitx_config" .gitignore
}

@test "python project generates python-specific ignores" {
  touch requirements.txt

  run ./bin/securegitx.sh

  [ "$status" -eq 0 ]
  grep -q "__pycache__/" .gitignore
  grep -q ".venv/" .gitignore
}

@test "node project generates node-specific ignores" {
  touch package.json tsconfig.json
  run ./bin/securegitx.sh

  [[ "$status" -eq 0 ]]
  grep -q "node_modules/" .gitignore
  grep -q "dist/" .gitignore
}

@test "AUTO_GITIGNORE=false prevents automatic creation" {
  echo 'AUTO_GITIGNORE=false' > .securegitx_config
  run ./bin/securegitx.sh

  [[ "$status" -eq 0 ]]
  [ ! -f .gitignore ] || ! grep -q "Injected by SecureGitX" .gitignore
}
