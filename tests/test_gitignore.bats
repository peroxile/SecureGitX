#!/usr/bin/env bats

load "${BATS_TEST_DIRNAME}/helpers/helper.bash"

@test "Creates .gitignore with SecureGitX marker" {
  git config --local user.name "Tester"
  git config --local user.email "tester@users.noreply.github.com"

  run "${BATS_TEST_DIRNAME}/../bin/securegitx.sh"

  [[ -f ".gitignore" ]]
  grep -q "Injected by SecureGitX" .gitignore
}

@test "Appends config file to existing .gitignore" {
  git config --local user.name "Tester"
  git config --local user.email "tester@users.noreply.github.com"

  echo "*.log" > .gitignore

  run "${BATS_TEST_DIRNAME}/../bin/securegitx.sh"

  grep -q ".securegitx_config" .gitignore
}
