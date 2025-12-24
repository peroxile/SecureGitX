#!/usr/bin/env bats

load "${BATS_TEST_DIRNAME}/helpers/helper.bash"

@test "Detects tracked sensitive file" {
  git config --local user.name "Tester"
  git config --local user.email "tester@users.noreply.github.com"

  echo "secret" > .env
  git add .env

  run "${BATS_TEST_DIRNAME}/../bin/securegitx.sh" "msg"

  [[ "$status" -ne 0 ]]
  [[ "$output" =~ "Tracked sensitive file" ]]
}

@test "Passes when no sensitive files tracked" {
  git config --local user.name "Tester"
  git config --local user.email "tester@users.noreply.github.com"

  echo "safe" > readme.md
  git add readme.md

  run "${BATS_TEST_DIRNAME}/../bin/securegitx.sh" "msg"

  [[ "$status" -eq 0 ]]
}
