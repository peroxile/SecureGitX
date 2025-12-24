#!/usr/bin/env bats

load "${BATS_TEST_DIRNAME}/helpers/helper.bash"

@test "Fails if git user.name is missing" {
  git config --local user.email "test@example.com"

  run "${BATS_TEST_DIRNAME}/../bin/securegitx.sh" "msg"

  [[ "$status" -ne 0 ]]
}

@test "Fails if git user.email is missing" {
  git config --local user.name "Tester"

  run "${BATS_TEST_DIRNAME}/../bin/securegitx.sh" "msg"

  [[ "$status" -ne 0 ]]
}

@test "Passes with valid identity and staged file" {
  git config --local user.name "Tester"
  git config --local user.email "tester@users.noreply.github.com"

  echo "ok" > file.txt
  git add file.txt

  run "${BATS_TEST_DIRNAME}/../bin/securegitx.sh" "secure commit"

  [[ "$status" -eq 0 ]]
}