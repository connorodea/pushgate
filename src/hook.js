import path from 'node:path';
import { loadConfig, appendAuditLog } from './config.js';
import { sendAlert, requestMobileApproval } from './ntfy.js';
import { getSystemIdleSeconds } from './idle.js';
import { evaluateGatePolicy } from './policy.js';

// Only exempt Pushgate's own registered MCP tools (not arbitrary third-party tools containing "pushgate")
const SELF_MCP_TOOL_RE = /^(?:mcp__pushgate__(?:pushgate_)?|pushgate_)(notify|ask|gate)$/i;

async function readStdinJson() {
  if (process.stdin.isTTY) {
    return {};
  }
  try {
    const chunks = [];
    for await (const chunk of process.stdin) {
      chunks.push(Buffer.from(chunk));
    }
    const raw = Buffer.concat(chunks).toString('utf-8').trim();
    return raw ? JSON.parse(raw) : {};
  } catch (err) {
    process.stderr.write(`[pushgate] Invalid JSON on stdin: ${err.message}\n`);
    return {};
  }
}

function emitJsonAndExit(obj) {
  process.stdout.write(JSON.stringify(obj) + '\n');
  process.exit(0);
}

export function truncate(str, maxLen) {
  if (!str) return '';
  const chars = Array.from(String(str));
  return chars.length > maxLen ? chars.slice(0, maxLen - 1).join('') + '…' : chars.join('');
}

function agentDisplayName(agent) {
  switch (agent) {
    case 'claude':
      return 'Claude Code';
    case 'cursor':
      return 'Cursor';
    case 'codex':
      return 'Codex CLI';
    default:
      return 'Gemini CLI';
  }
}

export function formatToolSummary(agent, toolName, toolInput = {}, cwdOverride = '') {
  const label = agentDisplayName(agent);
  const inputObj = toolInput && typeof toolInput === 'object' ? toolInput : {};
  const projectDir =
    cwdOverride ||
    process.env.GEMINI_PROJECT_DIR ||
    process.env.GEMINI_CWD ||
    process.env.CLAUDE_PROJECT_DIR ||
    process.cwd();
  const projectName = path.basename(projectDir) || 'workspace';

  if (toolName === 'run_shell_command' || toolName === 'Bash' || toolName === 'beforeShellExecution') {
    const cmd = inputObj.command || JSON.stringify(toolInput);
    const dir = inputObj.dir_path ? ` (in ${inputObj.dir_path})` : '';
    return {
      projectName,
      title: `${label} needs approval [${projectName}]`,
      body: `Shell${dir}:\n${truncate(cmd, 280)}`
    };
  }

  if (toolName === 'write_file' || toolName === 'Write') {
    const filePath = inputObj.file_path || inputObj.path || 'unknown file';
    const lines = String(inputObj.content || '').split('\n').length;
    return {
      projectName,
      title: `${label} write file [${projectName}]`,
      body: `Write ${filePath} (${lines} lines)`
    };
  }

  if (
    toolName === 'replace' ||
    toolName === 'Edit' ||
    toolName === 'MultiEdit' ||
    toolName.includes('edit') ||
    toolName.includes('replace')
  ) {
    const filePath = inputObj.file_path || inputObj.path || 'unknown file';
    const editPreview = Array.isArray(inputObj.edits)
      ? `(${inputObj.edits.length} hunks) ${inputObj.edits[0]?.new_string || ''}`
      : inputObj.instruction || inputObj.new_string || '';
    return {
      projectName,
      title: `${label} edit file [${projectName}]`,
      body: `Modify ${filePath}\n${truncate(editPreview, 180)}`
    };
  }

  return {
    projectName,
    title: `${label} tool call [${projectName}]`,
    body: `${toolName}: ${truncate(JSON.stringify(toolInput), 240)}`
  };
}

/**
 * Shared decision engine across Gemini CLI, Claude Code, and Cursor pre-tool hooks.
 * Returns normalized outcome:
 *   { outcome: 'pass' | 'allow' | 'deny', reason?, source?, risk? }
 */
async function executeGateDecision({ agent, toolName, toolInput, sessionId, cwd }) {
  if (SELF_MCP_TOOL_RE.test(toolName)) {
    return { outcome: 'pass' };
  }

  const config = loadConfig();
  if (!config || !config.topic || config.mode === 'off' || config.mode === 'notify-only') {
    return { outcome: 'pass' };
  }

  const idleSecs =
    config.mode === 'away' || config.mode === 'smart'
      ? getSystemIdleSeconds()
      : Infinity;

  const inputObj = toolInput && typeof toolInput === 'object' ? toolInput : {};
  const { projectName, title, body } = formatToolSummary(agent, toolName, toolInput, cwd);

  const policy = evaluateGatePolicy(config, {
    toolName,
    toolInput,
    projectName,
    idleSecs
  });

  if (policy.action === 'pass') {
    if (config.mode === 'away' || config.mode === 'smart') {
      process.stderr.write(`[pushgate] ${policy.reason}. Skipping mobile gate.\n`);
    }
    return { outcome: 'pass', risk: policy.risk };
  }

  if (policy.action === 'allow') {
    appendAuditLog({
      event: 'BeforeTool',
      agent,
      project: projectName,
      tool: toolName,
      command: truncate(inputObj.command || inputObj.file_path || inputObj.path || '', 160),
      risk: policy.risk,
      decision: 'AUTO_ALLOW',
      source: policy.ruleName ? `rule:${policy.ruleName}` : 'smart-policy',
      latencyMs: 0,
      sessionId: sessionId || null
    });
    return { outcome: 'allow', reason: policy.reason, source: 'policy', risk: policy.risk };
  }

  if (policy.action === 'deny') {
    appendAuditLog({
      event: 'BeforeTool',
      agent,
      project: projectName,
      tool: toolName,
      command: truncate(inputObj.command || inputObj.file_path || inputObj.path || '', 160),
      risk: policy.risk,
      decision: 'POLICY_DENY',
      source: policy.ruleName ? `rule:${policy.ruleName}` : 'policy',
      latencyMs: 0,
      sessionId: sessionId || null
    });
    return { outcome: 'deny', reason: policy.reason, source: 'policy', risk: policy.risk };
  }

  const riskBadge = policy.risk === 'high' ? ' [HIGH RISK]' : '';
  const routedNote = policy.approverLabel ? ` (Routed to ${policy.approverLabel})` : '';
  process.stderr.write(`[pushgate] Waiting for approval on "${toolName}"${riskBadge}${routedNote}...\n`);

  const startedAt = Date.now();
  try {
    const result = await requestMobileApproval(config, {
      title: `${title}${riskBadge}`,
      body,
      agent,
      project: projectName,
      tool: toolName,
      risk: policy.risk,
      topicOverride: policy.routeTopic,
      approverLabel: policy.approverLabel
    });

    const latencyMs = Date.now() - startedAt;

    appendAuditLog({
      event: 'BeforeTool',
      agent,
      project: projectName,
      tool: toolName,
      command: truncate(inputObj.command || inputObj.file_path || inputObj.path || '', 160),
      risk: policy.risk,
      decision: result.decision,
      source: result.source || 'mobile',
      routedTopic: policy.routeTopic !== config.topic ? policy.routeTopic : undefined,
      latencyMs,
      sessionId: sessionId || null
    });

    if (result.decision === 'ALLOW') {
      process.stderr.write(`[pushgate] Approved via ${result.source || 'mobile'}.\n`);
      return {
        outcome: 'allow',
        source: result.source || 'mobile',
        risk: policy.risk
      };
    }

    if (result.decision === 'DENY') {
      process.stderr.write(`[pushgate] Denied via ${result.source || 'mobile'}.\n`);
      return {
        outcome: 'deny',
        source: result.source || 'mobile',
        risk: policy.risk,
        reason: `The user explicitly denied executing ${toolName} from ${result.source || 'their mobile device'}. Do not retry this exact command without asking for an alternative approach.`
      };
    }

    if (config.timeoutAction === 'fallback-terminal') {
      process.stderr.write(`[pushgate] Approval timed out. Falling back to terminal.\n`);
      return { outcome: 'pass', risk: policy.risk };
    }

    return {
      outcome: 'deny',
      source: 'timeout',
      risk: policy.risk,
      reason: `Mobile approval timed out after ${config.timeoutSec} seconds.`
    };
  } catch (err) {
    process.stderr.write(`[pushgate] Network error (${err.message}). Leaving decision to terminal.\n`);
    return { outcome: 'pass', risk: policy.risk };
  }
}

async function dispatchTurnCompletion({ agent, message, sessionId, cwd }) {
  const config = loadConfig();
  if (!config || (!config.topic && !config.bell) || config.mode === 'off') {
    return;
  }

  if (config.mode === 'away') {
    const idleSecs = getSystemIdleSeconds();
    if (idleSecs < (config.awayThresholdSec ?? 60)) {
      return;
    }
  }

  const projectDir =
    cwd ||
    process.env.GEMINI_PROJECT_DIR ||
    process.env.GEMINI_CWD ||
    process.env.CLAUDE_PROJECT_DIR ||
    process.cwd();
  const projectName = path.basename(projectDir) || 'workspace';
  const label = agentDisplayName(agent);
  const responseSnippet = truncate(
    String(message || 'Task finished and awaiting next instruction.').replace(/\s+/g, ' ').trim(),
    220
  );

  try {
    await sendAlert(config, {
      title: `${label} finished [${projectName}]`,
      message: responseSnippet,
      tags: ['white_check_mark', 'sparkles'],
      priority: 3
    });
    appendAuditLog({
      event: 'AfterAgent',
      agent,
      project: projectName,
      sessionId: sessionId || null
    });
  } catch (err) {
    process.stderr.write(`[pushgate] Alert delivery failed: ${err.message}\n`);
  }
}

// ─── Gemini CLI Hooks ───────────────────────────────────────────────────────

export async function runBeforeToolHook() {
  const input = await readStdinJson();
  const res = await executeGateDecision({
    agent: 'gemini',
    toolName: input.tool_name || 'unknown_tool',
    toolInput: input.tool_input || {},
    sessionId: process.env.GEMINI_SESSION_ID || input.session_id || null,
    cwd: input.cwd || ''
  });

  if (res.outcome === 'allow') {
    const badge = res.source === 'policy' ? '⚡ Auto-allowed by Pushgate smart policy.' : '📱 Approved from mobile lock screen.';
    return emitJsonAndExit({
      decision: 'allow',
      systemMessage: badge
    });
  }

  if (res.outcome === 'deny') {
    const badge = res.source === 'timeout' ? '⏱️ Mobile approval timed out — action blocked.' : '🛑 Denied via Pushgate.';
    return emitJsonAndExit({
      decision: 'deny',
      reason: res.reason,
      systemMessage: badge
    });
  }

  return emitJsonAndExit({});
}

export async function runAfterAgentHook() {
  const input = await readStdinJson();
  await dispatchTurnCompletion({
    agent: 'gemini',
    message: input.prompt_response,
    sessionId: process.env.GEMINI_SESSION_ID || input.session_id || null,
    cwd: input.cwd || ''
  });
  return emitJsonAndExit({});
}

// ─── Claude Code Hooks ──────────────────────────────────────────────────────

export async function runClaudePreToolHook() {
  const input = await readStdinJson();
  const res = await executeGateDecision({
    agent: 'claude',
    toolName: input.tool_name || 'unknown_tool',
    toolInput: input.tool_input || {},
    sessionId: input.session_id || null,
    cwd: input.cwd || ''
  });

  if (res.outcome === 'allow') {
    return emitJsonAndExit({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'allow',
        permissionDecisionReason: res.reason || 'Approved via Pushgate'
      }
    });
  }

  if (res.outcome === 'deny') {
    return emitJsonAndExit({
      hookSpecificOutput: {
        hookEventName: 'PreToolUse',
        permissionDecision: 'deny',
        permissionDecisionReason: res.reason || 'Denied via Pushgate'
      }
    });
  }

  return emitJsonAndExit({});
}

export async function runClaudeStopHook() {
  const input = await readStdinJson();
  if (input.stop_hook_active) {
    return emitJsonAndExit({});
  }
  await dispatchTurnCompletion({
    agent: 'claude',
    message: input.last_assistant_message || input.transcript_summary || '',
    sessionId: input.session_id || null,
    cwd: input.cwd || ''
  });
  return emitJsonAndExit({});
}

// ─── Cursor Hooks ───────────────────────────────────────────────────────────

export async function runCursorBeforeShellHook() {
  const input = await readStdinJson();
  const res = await executeGateDecision({
    agent: 'cursor',
    toolName: 'beforeShellExecution',
    toolInput: { command: input.command || '' },
    sessionId: input.conversation_id || null,
    cwd: input.cwd || (Array.isArray(input.workspace_roots) ? input.workspace_roots[0] : '')
  });

  if (res.outcome === 'allow') {
    return emitJsonAndExit({ permission: 'allow' });
  }
  if (res.outcome === 'deny') {
    return emitJsonAndExit({
      permission: 'deny',
      user_message: 'Blocked via Pushgate',
      agent_message: res.reason
    });
  }
  return emitJsonAndExit({ permission: 'ask' });
}

export async function runCursorBeforeMcpHook() {
  const input = await readStdinJson();
  const res = await executeGateDecision({
    agent: 'cursor',
    toolName: input.tool_name || 'mcp_tool',
    toolInput: input.tool_input || {},
    sessionId: input.conversation_id || null,
    cwd: input.cwd || ''
  });

  if (res.outcome === 'allow') {
    return emitJsonAndExit({ permission: 'allow' });
  }
  if (res.outcome === 'deny') {
    return emitJsonAndExit({
      permission: 'deny',
      user_message: 'Blocked via Pushgate',
      agent_message: res.reason
    });
  }
  return emitJsonAndExit({ permission: 'ask' });
}

export async function runCursorStopHook() {
  const input = await readStdinJson();
  await dispatchTurnCompletion({
    agent: 'cursor',
    message: input.status ? `Cursor agent finished (${input.status}).` : 'Cursor agent finished.',
    sessionId: input.conversation_id || null,
    cwd: input.cwd || ''
  });
  return emitJsonAndExit({});
}

// ─── Codex CLI Hook ─────────────────────────────────────────────────────────

export async function runCodexNotifyHook(rawArg) {
  let payload = {};
  if (rawArg) {
    try {
      payload = JSON.parse(rawArg);
    } catch {
      payload = {};
    }
  } else {
    payload = await readStdinJson();
  }

  await dispatchTurnCompletion({
    agent: 'codex',
    message: payload['last-assistant-message'] || payload.message || 'Codex turn complete.',
    sessionId: payload['thread-id'] || null,
    cwd: payload.cwd || ''
  });
  process.exit(0);
}
