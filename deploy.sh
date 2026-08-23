#!/bin/sh
# Deploy toolbox to the public web root. Run tests first; abort on failure.
set -e
cd "$(dirname "$0")"
node --test tools/*/*.test.js
# .git must never reach the web root: its config holds the GitHub access token.
rsync -av --delete \
  --exclude 'deploy.sh' \
  --exclude '.git' \
  --exclude '.gitignore' \
  -e "ssh -i ~/.ssh/id_ed25519 -o StrictHostKeyChecking=accept-new" \
  ./ pub@69.55.60.153:/
echo "Deployed. Verify: curl -s -o /dev/null -w '%{http_code}\n' https://unsent.tools/"
