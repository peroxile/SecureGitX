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

@test "blocks tracked sensitive filenames" {
  echo "SECRET=123" > .env
  git add .env
  git commit -q -m "add env"

  run ./bin/securegitx.sh

  [[ "$status" -ne 0 ]]
  [[ "$output" = *"Tracked sensitive file: .env"* ]]
}

@test "blocks staged sensitive content via python analyzer" {
  cat > secrets.py <<'EOF'
secrets = {
    "generic": "SECRET",
    "github": "ghp_.fake_token",
    "stripe": "sk_live.fake_key",
    "aws_id": "AKIA.fake_id",
    "aws_key": "aws_access_key.fake",
}
EOF

  git add secrets.py

  run ./bin/securegitx.sh "bad commit"

  [[ "$status" -ne 0 ]]
  [[ "$output" = *"Sensitive content detected"* ]]
}


@test "does not flag low-entropy documentation as secret (false-positive guard)" {
  echo 'echo "username@users.noreply.github.com"' > setup.sh
  git add setup.sh

  run ./bin/securegitx.sh "doc commit"

  [[ "$status" -eq 0 ]]
}

@test "allows clean staged files to commit successfully" {
  echo "print('hello world')" > app.py
  git add app.py

  run ./bin/securegitx.sh "clean commit"

  [[ "$status" -eq 0 ]]
  [[ "$output" =~ "Commit successful" ]]
  
  git log -1 --oneline | grep -q "clean commit"
}