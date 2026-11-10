# Pushgate

Open, zero-dependency, self-hostable **human-in-the-loop push notifications, lock-screen questions, and cryptographic tool approvals** for AI coding agents (**Gemini CLI**, **Claude Code**, **Cursor**, **OpenAI Codex CLI**, and any **MCP** client).

Built as an open-protocol alternative to hosted agent-notification platforms like Pushary — no proprietary cloud lock-in, works out-of-the-box with [ntfy](https://ntfy.sh) or your own self-hosted ntfy relay, plus a local desktop bell and real-time web control plane.

---

## Core Capabilities

1. **Gate (`BeforeTool` / `PreToolUse` / `beforeShellExecution` / MCP `pushgate_gate`)**
   - Intercepts shell commands, file writes/edits, and external MCP calls before execution.
   - Delivers actionable **Approve** / **Deny** buttons directly to your iOS/Android lock screen and local dashboard.
   - **Cryptographically verified**: Every request generates a unique nonce and HMAC-SHA256 signatures (`~/.pushgate/config.json`, `0600`) verified with constant-time comparison so decisions cannot be spoofed even over a public relay.
2. **Ask (`pushgate ask` / MCP `pushgate_ask`)**
   - Instead of stalling in a background terminal waiting for input, agents send yes/no or multiple-choice prompts straight to your lock screen and local dashboard, blocking until you tap a choice.
3. **Notify (`AfterAgent` / `Stop` / `pushgate notify` / MCP `pushgate_notify`)**
   - Instant lock-screen push and/or macOS/Linux desktop banner + chime when long-running agent turns, builds, or deployments finish.
4. **Smart Risk Engine & Team Routing Rules (`smart` mode + `pushgate rule`)**
   - Auto-allows safe read-only commands (`git status`, `ls`, `rg`, `npm test`, `pytest`) while always gating high-risk commands (`rm -rf`, `sudo`, `git push --force`, `DROP TABLE`, `terraform destroy`, `kubectl delete`, `.env` edits).
   - Route specific patterns (e.g., production deploys or infra repos) to a team lead's topic with full attribution in `~/.pushgate/audit.jsonl`.
5. **Local Real-Time Dashboard (`pushgate dashboard`)**
   - Built-in web UI (`http://127.0.0.1:4747`) with live SSE updates to approve/deny pending gates from your browser, answer agent questions, toggle modes/bell, configure routing rules, and search the audit trail.

---

## Quick Start

```bash
git clone https://github.com/connorodea/pushgate.git
cd pushgate
npm link

# Interactive phone pairing + hook/MCP installation (Gemini CLI, Claude Code, Cursor, Codex)
pushgate setup
```

---

## CLI Reference

```text
pushgate setup [--agents all]   Interactive setup, phone pairing & multi-agent hook/MCP install
pushgate test [--roundtrip]     Send a test push (add --roundtrip to test lock-screen Approve/Deny)
pushgate mode [mode]            Switch mode: always | smart | away | notify-only | off
pushgate bell [on|off]          Toggle local desktop Notification Center banners + terminal bell
pushgate notify <title> [msg]   Send a direct push/desktop notification from scripts or CI
pushgate ask <q> [--options ..] Ask a lock-screen multiple-choice question and print the answer
pushgate gate -- <cmd...>       Gate any shell command behind cryptographic mobile approval
pushgate dashboard [--port N]   Launch live local web dashboard & real-time approval console
pushgate rule <list|add|remove> Manage smart policy & team topic routing rules
pushgate mcp                    Start stdio Model Context Protocol server (notify / ask / gate)
pushgate doctor                 Verify config, agent hooks, and push relay connectivity
pushgate logs [-n 25] [--json]  Show recent audit trail of gated tool decisions
pushgate uninstall              Remove Pushgate hooks & MCP entries across coding agents
```

---

## Gate Modes

| Mode | Behavior |
| --- | --- |
| `always` | Requires mobile/dashboard approval on every gated tool call; sends completion pushes. |
| `smart` | Auto-allows safe read-only commands, gates medium-risk tools when away from desk, and **always** gates high-risk operations (`rm -rf`, `sudo`, force-push, deploys). |
| `away` | Checks system HID idle time (`IOHIDSystem` on macOS, `xprintidle` on Linux) and only gates/notifies when idle >= `awayThresholdSec` (default `60s`). |
| `notify-only` | Skips pre-tool gates; sends turn-completion notifications. |
| `off` | Disables all gates and notifications without uninstalling hooks. |

---

## MCP Tools Exposed (`pushgate mcp`)

When installed via `pushgate setup`, coding agents gain direct access to three MCP tools:

- `pushgate_notify({ title, message, level })`
- `pushgate_ask({ question, options, title })`
- `pushgate_gate({ action, command, risk })`

---

## Testing

```bash
npm test
```
