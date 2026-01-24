#!/usr/bin/env bats

load helpers/helper.bash

setup() {
  setup_repo
}

teardown() {
  teardown_repo
}

@test "blocks tracked sensitive filenames" {
  echo "SECRET=123" > .env
  git add .env
  git commit -m "add env" -q

  run ./bin/securegitx.sh
  [ "$status" -ne 0 ]
  [[ "$output" =~ "Tracked sensitive file" ]]
}

@test "blocks staged sensitive content" {
  echo "SECRET=123" > secret.txt
  git add secret.txt
  run bin/securegitx.sh "Test commit"
  [ "$status" -ne 0 ]
  [[ "$output" =~ "Sensitive file staged: secret.txt" ]]
}

@test "does not flag documentation text as secret (entropy false-positive guard)" {
  echo 'printf "Copy your GitHub no-reply email (username@users.noreply.github.com)"' > readme.sh
  git add readme.sh

  run ./bin/securegitx.sh "doc commit"
  [ "$status" -eq 0 ]
}

@test "allows clean staged files to commit" {
  echo "print('hello')" > ok.py
  git add ok.py

  run ./bin/securegitx.sh "clean commit"
  [ "$status" -eq 0 ]
  git log -1 --oneline | grep -q "clean commit"
}
