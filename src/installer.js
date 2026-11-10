import fs from 'node:fs';
import path from 'node:path';
import os from 'node:os';

const HOOK_PREFIX = 'pushgate-';

function getPaths() {
  const home = os.homedir();
  const geminiDir = process.env.PUSHGATE_GEMINI_DIR || path.join(home, '.gemini');
  const claudeDir = process.env.PUSHGATE_CLAUDE_DIR || path.join(home, '.claude');
  const cursorDir = process.env.PUSHGATE_CURSOR_DIR || path.join(home, '.cursor');
  const codexDir = process.env.PUSHGATE_CODEX_DIR || path.join(home, '.codex');

  return {
    geminiDir,
    geminiSettingsPath: path.join(geminiDir, 'settings.json'),
    claudeDir,
    claudeSettingsPath: path.join(claudeDir, 'settings.json'),
    cursorDir,
    cursorHooksPath: path.join(cursorDir, 'hooks.json'),
    cursorMcpPath: path.join(cursorDir, 'mcp.json'),
    codexDir,
    codexConfigPath: path.join(codexDir, 'config.toml')
  };
}

function readJsonWithBackup(filePath) {
  if (!fs.existsSync(filePath)) return {};
  const raw = fs.readFileSync(filePath, 'utf-8');
  fs.writeFileSync(`${filePath}.bak`, raw);
  return raw.trim() ? JSON.parse(raw) : {};
}

// ─── Gemini CLI ─────────────────────────────────────────────────────────────

export function installGeminiHooks(config, binPath, { withMcp = true } = {}) {
  const { geminiDir, geminiSettingsPath } = getPaths();
  fs.mkdirSync(geminiDir, { recursive: true });

  const settings = readJsonWithBackup(geminiSettingsPath);
  settings.hooks = settings.hooks || {};

  for (const eventName of ['BeforeTool', 'AfterAgent']) {
    if (Array.isArray(settings.hooks[eventName])) {
      settings.hooks[eventName] = settings.hooks[eventName].filter(
        group => !group.hooks?.some(h => h.name?.startsWith(HOOK_PREFIX))
      );
    } else {
      settings.hooks[eventName] = [];
    }
  }

  const timeoutMs = ((config.timeoutSec || 300) + 15) * 1000;

  settings.hooks.BeforeTool.push({
    matcher: config.gatedTools || 'run_shell_command|write_file|replace|mcp__.*',
    hooks: [
      {
        name: `${HOOK_PREFIX}gate`,
        type: 'command',
        command: `"${process.execPath}" "${binPath}" hook before-tool`,
        description: 'Mobile lock-screen approval gate for shell commands, writes, and edits',
        timeout: timeoutMs
      }
    ]
  });

  settings.hooks.AfterAgent.push({
    matcher: '*',
    hooks: [
      {
        name: `${HOOK_PREFIX}complete`,
        type: 'command',
        command: `"${process.execPath}" "${binPath}" hook after-agent`,
        description: 'Push notification when Gemini CLI completes an agent turn',
        timeout: 15000
      }
    ]
  });

  if (withMcp) {
    settings.mcpServers = settings.mcpServers || {};
    settings.mcpServers.pushgate = {
      command: process.execPath,
      args: [binPath, 'mcp']
    };
  }

  fs.writeFileSync(geminiSettingsPath, JSON.stringify(settings, null, 2) + '\n');
  return geminiSettingsPath;
}

export function uninstallGeminiHooks() {
  const { geminiSettingsPath } = getPaths();
  if (!fs.existsSync(geminiSettingsPath)) return false;
  const settings = JSON.parse(fs.readFileSync(geminiSettingsPath, 'utf-8'));

  if (settings.hooks) {
    for (const eventName of Object.keys(settings.hooks)) {
      if (Array.isArray(settings.hooks[eventName])) {
        settings.hooks[eventName] = settings.hooks[eventName].filter(
          group => !group.hooks?.some(h => h.name?.startsWith(HOOK_PREFIX))
        );
      }
    }
  }

  if (settings.mcpServers?.pushgate) {
    delete settings.mcpServers.pushgate;
  }

  fs.writeFileSync(geminiSettingsPath, JSON.stringify(settings, null, 2) + '\n');
  return true;
}

export function checkGeminiHooksInstalled() {
  const { geminiSettingsPath } = getPaths();
  if (!fs.existsSync(geminiSettingsPath)) return { installed: false, path: geminiSettingsPath };
  try {
    const settings = JSON.parse(fs.readFileSync(geminiSettingsPath, 'utf-8'));
    const hasGate = settings.hooks?.BeforeTool?.some(g =>
      g.hooks?.some(h => h.name === `${HOOK_PREFIX}gate`)
    );
    const hasComplete = settings.hooks?.AfterAgent?.some(g =>
      g.hooks?.some(h => h.name === `${HOOK_PREFIX}complete`)
    );
    const hasMcp = Boolean(settings.mcpServers?.pushgate);
    return {
      installed: Boolean(hasGate && hasComplete),
      hasGate: Boolean(hasGate),
      hasComplete: Boolean(hasComplete),
      hasMcp,
      path: geminiSettingsPath
    };
  } catch {
    return { installed: false, path: geminiSettingsPath };
  }
}

// ─── Claude Code ────────────────────────────────────────────────────────────

export function installClaudeHooks(config, binPath) {
  const { claudeDir, claudeSettingsPath } = getPaths();
  fs.mkdirSync(claudeDir, { recursive: true });

  const settings = readJsonWithBackup(claudeSettingsPath);
  settings.hooks = settings.hooks || {};

  const preCmd = `"${process.execPath}" "${binPath}" hook claude-pre-tool`;
  const stopCmd = `"${process.execPath}" "${binPath}" hook claude-stop`;

  for (const eventName of ['PreToolUse', 'Stop']) {
    if (Array.isArray(settings.hooks[eventName])) {
      settings.hooks[eventName] = settings.hooks[eventName].filter(
        group => !group.hooks?.some(h => h.command?.includes('pushgate'))
      );
    } else {
      settings.hooks[eventName] = [];
    }
  }

  const timeoutSec = (config.timeoutSec || 300) + 15;

  settings.hooks.PreToolUse.push({
    matcher: 'Bash|Write|Edit|MultiEdit|mcp__.*',
    hooks: [
      {
        type: 'command',
        command: preCmd,
        timeout: timeoutSec
      }
    ]
  });

  settings.hooks.Stop.push({
    matcher: '*',
    hooks: [
      {
        type: 'command',
        command: stopCmd,
        timeout: 15
      }
    ]
  });

  fs.writeFileSync(claudeSettingsPath, JSON.stringify(settings, null, 2) + '\n');
  return claudeSettingsPath;
}

export function uninstallClaudeHooks() {
  const { claudeSettingsPath } = getPaths();
  if (!fs.existsSync(claudeSettingsPath)) return false;
  const settings = JSON.parse(fs.readFileSync(claudeSettingsPath, 'utf-8'));
  if (!settings.hooks) return false;

  for (const eventName of Object.keys(settings.hooks)) {
    if (Array.isArray(settings.hooks[eventName])) {
      settings.hooks[eventName] = settings.hooks[eventName].filter(
        group => !group.hooks?.some(h => h.command?.includes('pushgate'))
      );
    }
  }

  fs.writeFileSync(claudeSettingsPath, JSON.stringify(settings, null, 2) + '\n');
  return true;
}

export function checkClaudeHooksInstalled() {
  const { claudeSettingsPath } = getPaths();
  if (!fs.existsSync(claudeSettingsPath)) return { installed: false, path: claudeSettingsPath };
  try {
    const settings = JSON.parse(fs.readFileSync(claudeSettingsPath, 'utf-8'));
    const hasGate = settings.hooks?.PreToolUse?.some(g =>
      g.hooks?.some(h => h.command?.includes('claude-pre-tool'))
    );
    const hasComplete = settings.hooks?.Stop?.some(g =>
      g.hooks?.some(h => h.command?.includes('claude-stop'))
    );
    return {
      installed: Boolean(hasGate && hasComplete),
      hasGate: Boolean(hasGate),
      hasComplete: Boolean(hasComplete),
      path: claudeSettingsPath
    };
  } catch {
    return { installed: false, path: claudeSettingsPath };
  }
}

// ─── Cursor ─────────────────────────────────────────────────────────────────

export function installCursorHooks(config, binPath, { withMcp = true } = {}) {
  const { cursorDir, cursorHooksPath, cursorMcpPath } = getPaths();
  fs.mkdirSync(cursorDir, { recursive: true });

  const hooksFile = readJsonWithBackup(cursorHooksPath);
  hooksFile.version = hooksFile.version || 1;
  hooksFile.hooks = hooksFile.hooks || {};

  for (const ev of ['beforeShellExecution', 'beforeMCPExecution', 'stop']) {
    if (Array.isArray(hooksFile.hooks[ev])) {
      hooksFile.hooks[ev] = hooksFile.hooks[ev].filter(h => !h.command?.includes('pushgate'));
    } else {
      hooksFile.hooks[ev] = [];
    }
  }

  const timeoutSec = (config.timeoutSec || 300) + 15;

  hooksFile.hooks.beforeShellExecution.push({
    command: `"${process.execPath}" "${binPath}" hook cursor-before-shell`,
    timeout: timeoutSec
  });
  hooksFile.hooks.beforeMCPExecution.push({
    command: `"${process.execPath}" "${binPath}" hook cursor-before-mcp`,
    timeout: timeoutSec
  });
  hooksFile.hooks.stop.push({
    command: `"${process.execPath}" "${binPath}" hook cursor-stop`,
    timeout: 15
  });

  fs.writeFileSync(cursorHooksPath, JSON.stringify(hooksFile, null, 2) + '\n');

  if (withMcp) {
    const mcpData = readJsonWithBackup(cursorMcpPath);
    mcpData.mcpServers = mcpData.mcpServers || {};
    mcpData.mcpServers.pushgate = {
      command: process.execPath,
      args: [binPath, 'mcp']
    };
    fs.writeFileSync(cursorMcpPath, JSON.stringify(mcpData, null, 2) + '\n');
  }

  return cursorHooksPath;
}

export function uninstallCursorHooks() {
  const { cursorHooksPath, cursorMcpPath } = getPaths();
  let changed = false;

  if (fs.existsSync(cursorHooksPath)) {
    const hooksFile = JSON.parse(fs.readFileSync(cursorHooksPath, 'utf-8'));
    if (hooksFile.hooks) {
      for (const ev of Object.keys(hooksFile.hooks)) {
        if (Array.isArray(hooksFile.hooks[ev])) {
          hooksFile.hooks[ev] = hooksFile.hooks[ev].filter(h => !h.command?.includes('pushgate'));
        }
      }
      fs.writeFileSync(cursorHooksPath, JSON.stringify(hooksFile, null, 2) + '\n');
      changed = true;
    }
  }

  if (fs.existsSync(cursorMcpPath)) {
    const mcpData = JSON.parse(fs.readFileSync(cursorMcpPath, 'utf-8'));
    if (mcpData.mcpServers?.pushgate) {
      delete mcpData.mcpServers.pushgate;
      fs.writeFileSync(cursorMcpPath, JSON.stringify(mcpData, null, 2) + '\n');
      changed = true;
    }
  }

  return changed;
}

export function checkCursorHooksInstalled() {
  const { cursorHooksPath } = getPaths();
  if (!fs.existsSync(cursorHooksPath)) return { installed: false, path: cursorHooksPath };
  try {
    const hooksFile = JSON.parse(fs.readFileSync(cursorHooksPath, 'utf-8'));
    const hasShell = hooksFile.hooks?.beforeShellExecution?.some(h =>
      h.command?.includes('cursor-before-shell')
    );
    const hasStop = hooksFile.hooks?.stop?.some(h => h.command?.includes('cursor-stop'));
    return {
      installed: Boolean(hasShell && hasStop),
      hasGate: Boolean(hasShell),
      hasComplete: Boolean(hasStop),
      path: cursorHooksPath
    };
  } catch {
    return { installed: false, path: cursorHooksPath };
  }
}

// ─── Codex CLI ──────────────────────────────────────────────────────────────

const CODEX_BEGIN = '# >>> pushgate begin >>>';
const CODEX_END = '# <<< pushgate end <<<';

export function installCodexHooks(_config, binPath) {
  const { codexDir, codexConfigPath } = getPaths();
  fs.mkdirSync(codexDir, { recursive: true });

  let raw = '';
  if (fs.existsSync(codexConfigPath)) {
    raw = fs.readFileSync(codexConfigPath, 'utf-8');
    fs.writeFileSync(`${codexConfigPath}.bak`, raw);
    raw = stripCodexBlock(raw);
  }

  const hasTopLevelNotify = /^\s*notify\s*=/m.test(raw);
  const rootPrefix = !hasTopLevelNotify
    ? `${CODEX_BEGIN}\nnotify = [${JSON.stringify(process.execPath)}, ${JSON.stringify(binPath)}, "hook", "codex-notify"]\n${CODEX_END}\n\n`
    : '';

  const mcpSection = [
    CODEX_BEGIN,
    '[mcp_servers.pushgate]',
    `command = ${JSON.stringify(process.execPath)}`,
    `args = [${JSON.stringify(binPath)}, "mcp"]`,
    CODEX_END
  ].join('\n');

  const trimmed = raw.trim();
  const body = trimmed ? `${rootPrefix}${trimmed}\n\n${mcpSection}\n` : `${rootPrefix}${mcpSection}\n`;
  fs.writeFileSync(codexConfigPath, body);
  return codexConfigPath;
}

function stripCodexBlock(raw) {
  const re = new RegExp(`${CODEX_BEGIN}[\\s\\S]*?${CODEX_END}\\n?`, 'g');
  return raw.replace(re, '');
}

export function uninstallCodexHooks() {
  const { codexConfigPath } = getPaths();
  if (!fs.existsSync(codexConfigPath)) return false;
  const raw = fs.readFileSync(codexConfigPath, 'utf-8');
  const cleaned = stripCodexBlock(raw);
  fs.writeFileSync(codexConfigPath, cleaned);
  return true;
}

export function checkCodexHooksInstalled() {
  const { codexConfigPath } = getPaths();
  if (!fs.existsSync(codexConfigPath)) return { installed: false, path: codexConfigPath };
  try {
    const raw = fs.readFileSync(codexConfigPath, 'utf-8');
    const installed = raw.includes(CODEX_BEGIN) || raw.includes('codex-notify');
    return { installed, path: codexConfigPath };
  } catch {
    return { installed: false, path: codexConfigPath };
  }
}

// ─── Multi-Agent Orchestrators ──────────────────────────────────────────────

export const SUPPORTED_AGENTS = ['gemini', 'claude', 'cursor', 'codex'];

export function installAgentIntegrations(config, binPath, agents = ['gemini']) {
  const results = {};
  for (const agent of agents) {
    if (agent === 'gemini') results.gemini = installGeminiHooks(config, binPath);
    if (agent === 'claude') results.claude = installClaudeHooks(config, binPath);
    if (agent === 'cursor') results.cursor = installCursorHooks(config, binPath);
    if (agent === 'codex') results.codex = installCodexHooks(config, binPath);
  }
  return results;
}

export function uninstallAllAgentIntegrations(agents = SUPPORTED_AGENTS) {
  const results = {};
  for (const agent of agents) {
    if (agent === 'gemini') results.gemini = uninstallGeminiHooks();
    if (agent === 'claude') results.claude = uninstallClaudeHooks();
    if (agent === 'cursor') results.cursor = uninstallCursorHooks();
    if (agent === 'codex') results.codex = uninstallCodexHooks();
  }
  return results;
}

export function checkAllAgentIntegrations() {
  return {
    gemini: checkGeminiHooksInstalled(),
    claude: checkClaudeHooksInstalled(),
    cursor: checkCursorHooksInstalled(),
    codex: checkCodexHooksInstalled()
  };
}
