#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_DIR="${1:-$SCRIPT_DIR}"

echo "╭────────────────────────────────────────────────────────────╮"
echo "│            Bootstrapping Pushgate CLI Installer            │"
echo "╰────────────────────────────────────────────────────────────╯"

# 1. Verify Node.js >= 20
if ! command -v node >/dev/null 2>&1; then
  echo "❌ Error: Node.js is not installed. Please install Node.js v20 or higher."
  exit 1
fi

NODE_MAJOR=$(node -p "process.versions.node.split('.')[0]")
if [ "$NODE_MAJOR" -lt 20 ]; then
  echo "❌ Error: Pushgate requires Node.js >= 20 (found $(node -v))."
  exit 1
fi

# 2. Copy files if installing into a custom target directory
if [ "$INSTALL_DIR" != "$SCRIPT_DIR" ]; then
  echo "📁 Installing Pushgate into: $INSTALL_DIR"
  mkdir -p "$INSTALL_DIR/bin" "$INSTALL_DIR/src"
  cp "$SCRIPT_DIR/package.json" "$SCRIPT_DIR/README.md" "$INSTALL_DIR/"
  cp "$SCRIPT_DIR/bin/pushgate.js" "$INSTALL_DIR/bin/pushgate.js"
  cp "$SCRIPT_DIR/src/"*.js "$INSTALL_DIR/src/"
fi

chmod +x "$INSTALL_DIR/bin/pushgate.js"

# 3. Link 'pushgate' binary globally
echo "🔗 Linking 'pushgate' binary..."
if (cd "$INSTALL_DIR" && npm link --silent 2>/dev/null); then
  echo "✅ Linked globally via npm."
else
  LOCAL_BIN="$HOME/.local/bin"
  mkdir -p "$LOCAL_BIN"
  ln -sf "$INSTALL_DIR/bin/pushgate.js" "$LOCAL_BIN/pushgate"
  echo "✅ Symlinked to $LOCAL_BIN/pushgate"
  if [[ ":$PATH:" != *":$LOCAL_BIN:"* ]]; then
    echo "⚠️  Note: Add 'export PATH=\"\$HOME/.local/bin:\$PATH\"' to your ~/.zshrc or ~/.bashrc"
  fi
fi

# 4. Launch interactive onboarding unless PUSHGATE_SKIP_SETUP=1
if [ "${PUSHGATE_SKIP_SETUP:-0}" = "1" ]; then
  echo "✅ Pushgate linked! Run 'pushgate setup' whenever you are ready to pair your phone."
  exit 0
fi

if [ -t 0 ]; then
  "$INSTALL_DIR/bin/pushgate.js" setup
else
  "$INSTALL_DIR/bin/pushgate.js" setup < /dev/tty
fi
