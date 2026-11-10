# Changelog

All notable changes to **Pushgate** are documented in this running changelog.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Maintaining this running changelog**
> - Record an entry at any time: `npm run changelog -- --add <added|changed|fixed|security|removed> "Description"`
> - Sync unlogged git commits into `[Unreleased]`: `npm run changelog -- --sync-git`
> - Promote `[Unreleased]` to a new version: `npm run changelog -- --release <x.y.z>`

---

## [Unreleased]

### Added

- Running `CHANGELOG.md` and `scripts/changelog.js` (`npm run changelog`) workflow for continuous release tracking.
- Expanded `README.md` component-by-component operations guide covering CLI setup, multi-agent hooks, MCP server, smart policies, team routing, local web control plane, desktop bell, and self-hosted `ntfy` relays.

---

## [1.0.0] - 2026-11-09

### Added

- **Core CLI (`bin/pushgate.js`)**: Zero-dependency Node.js (>= 20) CLI with `setup`, `test --roundtrip`, `mode`, `bell`, `notify`, `ask`, `gate -- <cmd>`, `dashboard`, `rule`, `mcp`, `doctor`, `logs`, and `uninstall` commands, plus standalone `install.sh` bootstrapper.
- **Multi-Agent Lifecycle Hooks (`src/hook.js`, `src/installer.js`)**:
  - **Gemini CLI**: `BeforeTool` approval gate, `AfterAgent` completion alert, and `mcpServers.pushgate` auto-registration in `~/.gemini/settings.json`.
  - **Claude Code**: `PreToolUse` (`hookSpecificOutput` permission protocol) and `Stop` hooks in `~/.claude/settings.json`.
  - **Cursor**: `beforeShellExecution`, `beforeMCPExecution`, and `stop` hooks in `~/.cursor/hooks.json` plus `~/.cursor/mcp.json`.
  - **OpenAI Codex CLI**: Root-level `notify` hook and `[mcp_servers.pushgate]` registration in `~/.codex/config.toml`.
- **Model Context Protocol Server (`src/mcp.js`)**: Built-in stdio JSON-RPC 2.0 MCP server (auto-detecting both newline-delimited and `Content-Length` framed transports) exposing `pushgate_notify`, `pushgate_ask`, and `pushgate_gate`.
- **Cryptographic Mobile Lock-Screen Gate & Multi-Choice Prompts (`src/ntfy.js`)**:
  - Per-request nonces and 24-char HMAC-SHA256 signatures verified via `crypto.timingSafeEqual` on `ALLOW`, `DENY`, multiple-choice options, and dashboard free-text replies.
  - Optional `Authorization: Bearer <authToken>` header forwarding for private/self-hosted `ntfy` relays.
- **Smart Risk Policy & Team Routing Engine (`src/policy.js`)**:
  - `smart` mode auto-allowing verified read-only inspection commands while gating medium-risk actions when away and always gating high-risk destructive/deploy operations (`rm -rf`, `sudo`, force-pushes, SQL drops, `terraform`/`kubectl`, `.env` edits).
  - Regex-based custom rules (`pushgate rule`) to auto-allow, block, or route matching approvals to a team lead's topic.
- **System Idle Detection (`src/idle.js`)**: Hardware HID idle detection on macOS (`ioreg -c IOHIDSystem`) and Linux (`xprintidle`) powering `away` and `smart` modes.
- **Live Local Control Plane Dashboard (`src/dashboard.js`)**: Real-time `node:http` + Server-Sent Events (SSE) web UI (`http://127.0.0.1:4747`) for browser-based approvals, custom free-text `ask` responses, live mode/bell toggles, rule management, and searchable audit logs.
- **Local Desktop Banner & Terminal Bell (`src/desktop.js`)**: Native macOS Notification Center banners (`osascript` with `Glass` chime) and Linux `notify-send` alerts (`pushgate bell`).

### Security

- Prevented self-tampering and secret exfiltration in `smart` mode by classifying reads/edits targeting `~/.pushgate`, agent hook configs, `.git/hooks`, `.ssh`, shell profiles, and `.env*` files as `high` risk.
- Blocked multiline newline injection (`\r`/`\n`), shell chaining, `find -delete`/`-exec`, and `git branch -D` from matching read-only shell allowlists.
- Protected the local dashboard against DNS rebinding (`Host` allowlist) and cross-origin CSRF (`Origin` check + required `X-Pushgate-Client: 1` header + `Content-Security-Policy` / `X-Frame-Options: DENY`).
- Eliminated AppleScript string-escaping injection by passing notification title and body via `osascript` `on run argv` positional parameters.
- Replaced substring MCP self-bypass with strict tool-name matching (`SELF_MCP_TOOL_RE`) so third-party MCP tools containing `"pushgate"` are still gated.
- Enforced atomic `0600` POSIX file writes (`tmp + rename`) for `~/.pushgate/config.json` and pending state files, plus automatic `0600` permission repair in `pushgate doctor`.

### Fixed

- Handled multi-chunk (>300KB) piped JSON hook payloads asynchronously without `EAGAIN` truncation.
- Added automatic ntfy stream reconnection (`?since=all`) across premature proxy/NAT idle disconnects before `timeoutSec`.
- Added buffered line-queue prompting (`createLinePrompter`) so non-interactive piped `pushgate setup` runs never fail with `ERR_USE_AFTER_CLOSE`.
- Preserved Unicode surrogate pairs when truncating notification snippets and lock-screen button labels (`Array.from` code-point slicing).

[Unreleased]: https://github.com/connorodea/pushgate/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/connorodea/pushgate/releases/tag/v1.0.0
