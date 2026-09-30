#!/usr/bin/env bash
# Полная пересборка mod.js: свежий клиент игры -> webcrack ->
# postprocess -> engine_port -> mod.js.  Самодостаточная: работает и локально,
# и в GitHub Actions (см. .github/workflows/update_mod.yml).
set -euo pipefail

REPO_DIR="$(cd "$(dirname "$0")" && pwd)"
WORK="${TMPDIR:-/tmp}/client_latest"
rm -rf "$WORK" && mkdir -p "$WORK"

# --- node ---
if ! command -v node >/dev/null 2>&1; then
  mkdir -p "$HOME/.local/node"
  curl -fsSL https://nodejs.org/dist/v20.19.0/node-v20.19.0-linux-x64.tar.xz -o /tmp/node.tar.xz
  tar -xJf /tmp/node.tar.xz -C "$HOME/.local/node" --strip-components=1
fi
export PATH="$HOME/.local/node/bin:$PATH"

# --- python deps ---
python3 -c "import requests, bs4" 2>/dev/null \
  || python3 -m pip install --user -q requests beautifulsoup4

# --- webcrack + obfuscator ---
if ! command -v webcrack >/dev/null 2>&1; then
  cd "$WORK" && npm install webcrack --no-save >/dev/null 2>&1
fi
if [ ! -d "$WORK/node_modules/javascript-obfuscator" ]; then
  cd "$WORK" && npm install javascript-obfuscator --no-save >/dev/null 2>&1
fi
if command -v webcrack >/dev/null 2>&1; then
  WEBCRACK=webcrack
elif [ -x "$WORK/node_modules/.bin/webcrack" ]; then
  WEBCRACK="$WORK/node_modules/.bin/webcrack"
else
  WEBCRACK="npx --yes webcrack"
fi

cd "$WORK"

# --- свежий клиент ---
SITE="https://dev""ast.io"
UA='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36'
fetch() {
  # $1 url, $2 dest — прямой запрос, curl-impersonate (TLS-отпечаток
  # Chrome: Cloudflare режет обычный curl с IP GitHub Actions), затем прокси
  if curl -fsSL -A "$UA" "$1" -o "$2" && [ -s "$2" ]; then return 0; fi
  if [ ! -d /tmp/ci ]; then
    mkdir -p /tmp/ci
    curl -fsSL "https://github.com/lwthiker/curl-impersonate/releases/download/v0.6.1/curl-impersonate-v0.6.1.x86_64-linux-gnu.tar.gz" \
      -o /tmp/ci.tgz \
      && echo "fa1e1614f7ba69ccc66721a0f38be457a3647eb64c75d66974b56186e3316b12  /tmp/ci.tgz" | sha256sum -c - \
      && tar -xzf /tmp/ci.tgz -C /tmp/ci || true
  fi
  for w in /tmp/ci/curl_chrome* /tmp/ci/curl_ff*; do
    [ -x "$w" ] || continue
    if "$w" -fsSL "$1" -o "$2" >/dev/null 2>&1 && [ -s "$2" ]; then return 0; fi
  done
  if curl -fsSL -A "$UA" -G "https://api.allorigins.win/raw" --data-urlencode "url=$1" -o "$2" && [ -s "$2" ]; then return 0; fi
  if curl -fsSL -A "$UA" -G "https://api.codetabs.com/v1/proxy" --data-urlencode "quest=$1" -o "$2" && [ -s "$2" ]; then return 0; fi
  return 1
}
fetch "$SITE/" index.html
JS=$(grep -o 'js/[A-Za-z0-9_-]*\.js' index.html | head -1)
[ -n "$JS" ] || { echo "FAIL: client js not found"; exit 1; }
echo "client: $JS"
fetch "$SITE/$JS" client.js
[ -s client.js ] || { echo "FAIL: client empty"; exit 1; }

# клиент не менялся — пересборка не нужна (обход: ./rebuild.sh --force)
NEW_SHA=$(sha256sum client.js | cut -d' ' -f1)
if [ "${1:-}" != "--force" ] && [ -f "$REPO_DIR/state/client.sha256" ] \
   && [ "$NEW_SHA" = "$(cat "$REPO_DIR/state/client.sha256")" ] && [ -s "$REPO_DIR/mod.js" ]; then
  echo "client unchanged ($JS)"
  exit 0
fi

# --- деобфускация + постпроцесс ---
$WEBCRACK client.js -o out
python3 -c "import sys, pathlib; sys.path.insert(0, '$REPO_DIR'); import engine_tracker; engine_tracker.postprocess_dir(pathlib.Path('$WORK/out'))"

CLIENT_JS=$(find "$WORK/out" -name '*.js' -printf '%s %p\n' | sort -rn | head -1 | cut -d' ' -f2-)
[ -n "$CLIENT_JS" ] || { echo "FAIL: no deobfuscated js"; exit 1; }

# --- сборка мода ---
python3 "$REPO_DIR/engine_port.py" "$CLIENT_JS" -o /tmp/mod_new.js
node --check /tmp/mod_new.js

# --- обфускация перед публикацией ---
cd "$WORK"
NODE_PATH="$WORK/node_modules" node "$REPO_DIR/pack.js" /tmp/mod_new.js /tmp/mod_obf.js
node --check /tmp/mod_obf.js
cp /tmp/mod_obf.js "$REPO_DIR/mod.js"

# маркер версии клиента — по нему workflow решает, пересобирать ли
mkdir -p "$REPO_DIR/state"
sha256sum "$WORK/client.js" | cut -d' ' -f1 > "$REPO_DIR/state/client.sha256"

cd "$REPO_DIR"
git add mod.js state/client.sha256
if git diff --cached --quiet; then
  echo "mod.js unchanged"
else
  git commit -q -m "auto-update mod.js (client $JS)"
  git push origin main
  echo "DONE: mod.js updated ($JS)"
fi
