# Pushgate

**Open, zero-dependency, self-hostable human-in-the-loop push notifications, lock-screen questions, and cryptographically enforced tool approvals for AI coding agents.**

Pushgate intercepts sensitive actions across **Gemini CLI**, **Claude Code**, **Cursor**, **OpenAI Codex CLI**, and any **Model Context Protocol (MCP)** client — delivering actionable **Approve / Deny** buttons and multiple-choice questions straight to your iPhone/Android lock screen (via [ntfy](https://ntfy.sh) or your own self-hosted relay), your macOS/Linux desktop, and a built-in real-time local web control plane.

---

## Table of Contents

1. [Architecture Overview](#1-architecture-overview)
2. [Prerequisites & Installation](#2-prerequisites--installation)
3. [Initial Setup & Phone Pairing](#3-initial-setup--phone-pairing)
4. [Running Each Component](#4-running-each-component)
   - [4.1 Coding Agent Hooks (Gemini CLI, Claude Code, Cursor, Codex)](#41-coding-agent-hooks-gemini-cli-claude-code-cursor-codex)
   - [4.2 Model Context Protocol (MCP) Server (`pushgate mcp`)](#42-model-context-protocol-mcp-server-pushgate-mcp)
   - [4.3 Live Local Web Control Plane (`pushgate dashboard`)](#43-live-local-web-control-plane-pushgate-dashboard)
   - [4.4 Desktop Banner & Terminal Bell (`pushgate bell`)](#44-desktop-banner--terminal-bell-pushgate-bell)
   - [4.5 Gate Modes & Smart Risk Policy (`pushgate mode`)](#45-gate-modes--smart-risk-policy-pushgate-mode)
   - [4.6 Team Routing & Custom Policy Rules (`pushgate rule`)](#46-team-routing--custom-policy-rules-pushgate-rule)
   - [4.7 Standalone Shell / CI Primitives (`notify`, `ask`, `gate`)](#47-standalone-shell--ci-primitives-notify-ask-gate)
   - [4.8 Self-Hosted `ntfy` Relay & Private Auth](#48-self-hosted-ntfy-relay--private-auth)
5. [Configuration & File Locations](#5-configuration--file-locations)
6. [Diagnostics, Audit Trail & Uninstallation](#6-diagnostics-audit-trail--uninstallation)
7. [Development, Testing & Running Changelog](#7-development-testing--running-changelog)

---

## 1. Architecture Overview

```text
┌─────────────────────────────────────────────────────────────────────────┐
│ AI Coding Agents & Workflows                                            │
│  • Gemini CLI   • Claude Code   • Cursor   • Codex CLI   • Shell / CI   │
└───────────────┬─────────────────────────────────────────┬───────────────┘
                │ Native Lifecycle Hooks                  │ stdio JSON-RPC
                ▼                                         ▼
     ┌─────────────────────┐                   ┌─────────────────────┐
     │  src/hook.js        │                   │  src/mcp.js         │
     │  Pre-Tool & Stop    │                   │  • pushgate_notify  │
     └──────────┬──────────┘                   │  • pushgate_ask     │
                │                              │  • pushgate_gate    │
                └──────────────┬───────────────┘──────────┬──────────┘
                               ▼                          │
                    ┌─────────────────────┐               │
                    │  src/policy.js      │◄──────────────┘
                    │  • Smart Risk Tier  │  • System Idle (src/idle.js)
                    │  • Team Rules       │  • Audit Log (~/.pushgate/audit.jsonl)
                    └──────────┬──────────┘
                               │
         ┌─────────────────────┼─────────────────────┐
         ▼                     ▼                     ▼
┌─────────────────┐   ┌─────────────────┐   ┌─────────────────────────┐
│ ntfy Push Relay │   │ Desktop Banner  │   │ Local Web Dashboard     │
│ (src/ntfy.js)   │   │ (src/desktop.js)│   │ http://127.0.0.1:4747   │
│ iOS / Android   │   │ macOS osascript │   │ Live SSE Approve / Deny │
│ Lock-Screen     │   │ Linux notify    │   │ Free-Text Ask & Rules   │
│ HMAC-SHA256     │   │ + Terminal Bell │   │ (src/dashboard.js)      │
└─────────────────┘   └─────────────────┘   └─────────────────────────┘
```

**Cryptographic Approval Guarantee**: Every approval or multiple-choice prompt generates a one-time request ID and signs each button payload with 24-character HMAC-SHA256 tokens derived from your local `0600` secret (`~/.pushgate/config.json`), verified in constant time (`crypto.timingSafeEqual`). Even over a public push relay, forged responses are ignored.

---

## 2. Prerequisites & Installation

- **Runtime**: Node.js **v20.0.0 or newer** (`node -v`) — **zero external npm packages required**.
- **OS**: macOS or Linux.
- **Mobile App** *(recommended)*: Free open-source **ntfy** app on [iOS App Store](https://apps.apple.com/us/app/ntfy/id1625396347) or [Google Play](https://play.google.com/store/apps/details?id=io.heckel.ntfy).

### Option A: Clone & Link Globally (Recommended for Development)

```bash
git clone https://github.com/connorodea/pushgate.git
cd pushgate
npm link

# Verify CLI is on your PATH
pushgate --version
```

### Option B: Standalone Bootstrap Script

Installs into the repo directory (or pass a custom path like `~/.local/share/pushgate`), links the `pushgate` binary, and launches interactive setup:

```bash
./install.sh
# Or install to a custom directory without immediately running interactive setup:
PUSHGATE_SKIP_SETUP=1 ./install.sh "$HOME/.local/share/pushgate"
```

---

## 3. Initial Setup & Phone Pairing

Run the interactive onboarding wizard:

```bash
pushgate setup
```

What `pushgate setup` walks you through:

1. **Push Relay Server**: Defaults to `https://ntfy.sh` (or enter your self-hosted ntfy URL).
2. **Private Topic & Secret**: Generates a random topic (`pg-<16-hex>`) and a 48-hex HMAC secret stored in `~/.pushgate/config.json` (`0600`).
3. **Default Gate Mode**: Choose `always`, `smart`, `away`, or `notify-only`.
4. **Coding Agents to Integrate**: Auto-detects installed agent config directories (`gemini`, `claude`, `cursor`, `codex`, or pass `all` via `pushgate setup --agents all`).
5. **Phone Pairing & Live Roundtrip Test**:
   - Open the **ntfy** mobile app → tap **`+`** → subscribe to your `pg-...` topic.
   - Press **ENTER** in the terminal to receive both a completion notification and a live lock-screen **`[Approve]` / `[Deny]`** cryptographic roundtrip test.

> You can re-run tests anytime via `pushgate test` (alert only) or `pushgate test --roundtrip` (interactive lock-screen button test).

---

## 4. Running Each Component

### 4.1 Coding Agent Hooks (Gemini CLI, Claude Code, Cursor, Codex)

Once `pushgate setup` finishes, **restart any open coding agent sessions** so they load the newly installed hooks and MCP server. Existing third-party hooks in your agent configs are preserved, and `.bak` backups are created automatically.

| Agent | Config Wired by `pushgate setup` | Events Intercepted |
| --- | --- | --- |
| **Gemini CLI** | `~/.gemini/settings.json` | `BeforeTool` (gates shell, writes, edits, external MCP), `AfterAgent` (turn completion push), plus `mcpServers.pushgate` |
| **Claude Code** | `~/.claude/settings.json` | `PreToolUse` (`Bash\|Write\|Edit\|MultiEdit\|mcp__.*` via `hookSpecificOutput`), `Stop` (turn completion push) |
| **Cursor** | `~/.cursor/hooks.json` & `~/.cursor/mcp.json` | `beforeShellExecution`, `beforeMCPExecution`, `stop`, plus `mcpServers.pushgate` |
| **Codex CLI** | `~/.codex/config.toml` | Root `notify` turn-completion hook + `[mcp_servers.pushgate]` |

**Optional — Add Pushgate MCP tools to Claude Code CLI:**

```bash
claude mcp add --scope user pushgate -- pushgate mcp
```

---

### 4.2 Model Context Protocol (MCP) Server (`pushgate mcp`)

Pushgate ships a built-in stdio JSON-RPC 2.0 MCP server (auto-detecting both newline-delimited JSON and LSP-style `Content-Length` framing) so **any** MCP-compatible editor or agent harness (Windsurf, OpenCode, Claude Desktop, LangGraph) can proactively notify you, ask questions, or request approval.

To register manually in any MCP client config:

```json
{
  "mcpServers": {
    "pushgate": {
      "command": "pushgate",
      "args": ["mcp"]
    }
  }
}
```

**Tools exposed by `pushgate mcp`:**

| MCP Tool | Arguments | What It Does |
| --- | --- | --- |
| `pushgate_notify` | `{ title, message, level?: "info"\|"success"\|"warning"\|"error" }` | Fires an immediate mobile push and/or desktop banner when builds, tests, or background tasks finish or fail. |
| `pushgate_ask` | `{ question, options?: string[], title?: string }` | Sends a question with tap-to-reply buttons (first 3 on mobile lock screen, unlimited + free-text input in Dashboard) and blocks until you answer. |
| `pushgate_gate` | `{ action, command?: string, risk?: "low"\|"medium"\|"high" }` | Requests explicit HMAC-signed mobile/dashboard approval before executing a sensitive step. |

---

### 4.3 Live Local Web Control Plane (`pushgate dashboard`)

Run the zero-dependency real-time web console (powered by `node:http` + Server-Sent Events, hardened against DNS rebinding and CSRF):

```bash
# Start on default http://127.0.0.1:4747 and open in browser (macOS)
pushgate dashboard --open

# Or run on a custom port
pushgate dashboard --port 4800
```

From the dashboard you can:
- **Approve or Deny** pending agent gates in real time (races seamlessly alongside your phone — whichever you tap first wins and clears the pending state).
- **Answer `pushgate_ask` questions** via option buttons or a **custom free-text answer** input.
- **Switch Gate Mode** (`always`, `smart`, `away`, `notify-only`, `off`) and toggle **Desktop Bell** live.
- **Inspect Connected Coding Agents** and manage **Policy & Team Routing Rules**.
- **Search & Filter the Live Audit Trail** (timestamp, agent, project, command, risk tier, decision, source, and response latency).

---

### 4.4 Desktop Banner & Terminal Bell (`pushgate bell`)

Want local macOS Notification Center banners (`osascript` + `Glass` chime) or Linux `notify-send` alerts alongside (or without) mobile push notifications?

```bash
# Enable local desktop banners + terminal bell
pushgate bell on

# Disable local desktop banners
pushgate bell off

# Toggle current state
pushgate bell
```

---

### 4.5 Gate Modes & Smart Risk Policy (`pushgate mode`)

Switch modes at any time — changes take effect **immediately** on the very next tool call without restarting your coding agent:

```bash
pushgate mode          # View current mode
pushgate mode smart    # Recommended daily-driver mode
pushgate mode away     # Gate & alert only when idle >= awayThresholdSec (default 60s)
pushgate mode always   # Require approval on every gated tool call
pushgate mode notify-only
pushgate mode off
```

| Mode | `BeforeTool` / Pre-Tool Gate | `AfterAgent` / Stop Alert |
| --- | --- | --- |
| `always` | Always requires mobile/dashboard approval | Always sends alert |
| `smart` | **Low risk** (pure read-only `ls`, `git status`, `git diff`, `rg`, etc.) → **auto-allowed**.<br>**Medium risk** (standard writes/commands) → passes to terminal while active at desk, gates when idle.<br>**High risk** (`rm -rf`, `sudo`, force/main `git push`, `find -delete`/`-exec`, SQL `DROP`/`TRUNCATE`, `terraform`/`kubectl`/`wrangler deploy`, `.env`/SSH/agent-hook edits) → **always gated**. | Always sends alert |
| `away` | Gates only when OS HID idle >= `awayThresholdSec` (`60s` default) | Sends only when idle >= `awayThresholdSec` |
| `notify-only` | Skipped | Always sends alert |
| `off` | Disabled | Disabled |

---

### 4.6 Team Routing & Custom Policy Rules (`pushgate rule`)

Configure regex rules (evaluated before default mode logic) to auto-allow trusted patterns, hard-block forbidden actions, or route infrastructure/production approvals to a designated team lead's topic:

```bash
# Route production Terraform/Kubernetes/main-branch pushes to a team lead's ntfy topic
pushgate rule add "Prod Infra" "terraform\s+apply|kubectl\s+delete|git\s+push.*main" gate \
  --topic pg-infra-lead \
  --approver "Infra Lead"

# Hard-block destructive database drops outright
pushgate rule add "No SQL Drops" "drop\s+(table|database)" deny

# List configured rules with their indices
pushgate rule list

# Remove rule at index 1
pushgate rule remove 1
```

---

### 4.7 Standalone Shell / CI Primitives (`notify`, `ask`, `gate`)

Use Pushgate directly inside Makefiles, deploy scripts, cron jobs, or custom Python/TypeScript agent loops:

```bash
# 1. Send a one-off push/desktop notification
pushgate notify "Nightly Build Passed" "All 148 integration tests green."

# 2. Ask a multiple-choice question on your phone and capture the answer in bash
TARGET=$(pushgate ask "Which environment should we deploy?" --options "Staging,Production,Abort")
echo "Selected: $TARGET"

# 3. Wrap any shell command behind cryptographic mobile approval
#    (Executes the command ONLY if approved; exits with code 2 if denied/timed out)
pushgate gate -- npm publish --access public
pushgate gate -- terraform apply -auto-approve
```

---

### 4.8 Self-Hosted `ntfy` Relay & Private Auth

To keep 100% of notification traffic on your own infrastructure:

```bash
# 1. Start a self-hosted ntfy server (Docker)
docker run -d --name ntfy -p 8080:80 binwiederhier/ntfy serve

# 2. Point Pushgate at your relay during setup:
pushgate setup
# Enter server: http://your-server:8080 (or https://ntfy.yourdomain.com)
```

If your `ntfy` server requires access tokens (`tk_...`), add `"authToken": "tk_your_token"` to `~/.pushgate/config.json` — Pushgate automatically attaches `Authorization: Bearer <authToken>` to publishes, streams, and mobile lock-screen HTTP action callbacks.

---

## 5. Configuration & File Locations

All local state lives in `~/.pushgate` with strict owner-only (`0700` / `0600`) permissions:

| Path | Purpose |
| --- | --- |
| `~/.pushgate/config.json` | Relay URL, topic, HMAC secret, active mode, bell toggle, timeout settings, and routing rules (`0600`). |
| `~/.pushgate/audit.jsonl` | Append-only JSON Lines audit trail recording timestamp, actor, agent, project, tool/command, risk tier, decision, source (`mobile` / `dashboard` / `policy`), and latency (`0600`). |
| `~/.pushgate/pending/` | Ephemeral pending request state shared with `pushgate dashboard` (auto-cleaned on resolution, signal exit, or TTL expiry). |

Example `~/.pushgate/config.json`:

```json
{
  "server": "https://ntfy.sh",
  "topic": "pg-0123456789abcdef",
  "secret": "<48-char-hex-hmac-secret>",
  "authToken": "optional-ntfy-bearer-token",
  "mode": "smart",
  "bell": true,
  "awayThresholdSec": 60,
  "timeoutSec": 300,
  "timeoutAction": "deny",
  "gatedTools": "run_shell_command|write_file|replace|Bash|Write|Edit|MultiEdit|mcp__.*",
  "agents": ["gemini", "claude", "cursor", "codex"],
  "rules": []
}
```

> **`timeoutAction`**: Set to `"deny"` (default, fail-closed on unanswered mobile timeout) or `"fallback-terminal"` (defers unanswered timeouts back to your local terminal prompt).

---

## 6. Diagnostics, Audit Trail & Uninstallation

```bash
# Verify config permissions (auto-heals to 0600), hooked agents, and live push reachability
pushgate doctor

# View the last 25 audit trail decisions (human-readable table)
pushgate logs

# View the last 50 raw JSONL audit events
pushgate logs -n 50 --json

# Cleanly remove Pushgate hooks & MCP entries from all (or specific) coding agents
pushgate uninstall
pushgate uninstall --agents claude,cursor
```

---

## 7. Development, Testing & Running Changelog

### Run the Full Security & Integration Test Suite

```bash
npm test
```

Runs all end-to-end test suites against an in-memory streaming relay in isolated temporary directories (never touching your real `~/.pushgate` or agent configs).

### Update the Running Changelog ([CHANGELOG.md](./CHANGELOG.md))

Pushgate includes a zero-dependency changelog manager (`scripts/changelog.js`):

```bash
# View current [Unreleased] + latest release entries
npm run changelog

# Record a new change under [Unreleased] (added | changed | fixed | security | removed)
npm run changelog -- --add added "Support custom webhook tags"
npm run changelog -- --add fixed "Handle IPv6 loopback origin header"

# Sync unrecorded git commits into [Unreleased]
npm run changelog -- --sync-git

# Cut a new SemVer release (updates CHANGELOG.md, package.json, and bin/pushgate.js)
npm run changelog -- --release 1.1.0
```

---

## License

[MIT](./LICENSE)
