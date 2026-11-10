// Strictly pure read-only OS & git inspection commands (no arbitrary script runners or mutating flags)
const SAFE_READ_ONLY_SHELL_RE =
  /^(?:\s*)(ls|pwd|whoami|date|uname|which|cat|head|tail|wc|stat|file|rg|grep|git\s+(?:status|diff|log|show|rev-parse)|git\s+branch(?:\s+(?:-a|-r|--all|--remotes|--list|--show-current|-v|-vv))?|node\s+-v|npm\s+-v)(?:\s+[^\r\n;&|`$<>()]*)?$/i;

// Reject any command chaining, subshells, redirections, or multiline newline injection
const SHELL_UNSAFE_METACHARS_RE = /[\r\n;&|`$<>()]/;

const SELF_TAMPER_OR_SECRET_RE =
  /(\.pushgate\b|\bpushgate\s+(mode|uninstall|setup|rule)\b|\.gemini\/settings\.json|\.claude\/settings\.json|\.cursor\/(hooks|mcp)\.json|\.codex\/config\.toml|\.git\/(hooks|config)|\.bashrc|\.zshrc|\.ssh\/|id_rsa|id_ed25519|(^|[\/\s"'])(\.env(\.[a-zA-Z0-9_-]+)?)(['"\s]|$)|\.pem\b|\.key\b|credentials\.json|secrets?\.(json|ya?ml|toml))/i;

const HIGH_RISK_PATTERNS = [
  { re: SELF_TAMPER_OR_SECRET_RE, reason: 'Targets Pushgate/agent security config, credentials, or secrets' },
  { re: /\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|--recursive\b.*--force|-rf|-fr)\b/i, reason: 'Recursive forced deletion (rm -rf)' },
  { re: /\bfind\b.*\s-(delete|exec|execdir|ok)\b/i, reason: 'Destructive or arbitrary-exec find command' },
  { re: /\bsudo\b/i, reason: 'Privileged execution (sudo)' },
  { re: /\bgit\s+push\b.*(--force|-f\b|\bmain\b|\bmaster\b|\bprod)/i, reason: 'Force or protected-branch git push' },
  { re: /\bgit\s+reset\s+--hard\b|\bgit\s+clean\s+-[a-zA-Z]*f|\bgit\s+branch\s+-D\b/i, reason: 'Destructive git reset/clean/branch-delete' },
  { re: /\b(drop\s+(table|database|schema)|truncate\s+table|delete\s+from\s+\w+\s*;)/i, reason: 'Destructive SQL statement' },
  { re: /\b(terraform\s+(destroy|apply)|kubectl\s+(delete|apply)|helm\s+(uninstall|upgrade)|wrangler\s+deploy|flyctl\s+deploy|vercel\s+--prod)\b/i, reason: 'Infrastructure / production deployment action' },
  { re: /\b(npm\s+publish|cargo\s+publish|twine\s+upload|gh\s+release\s+create)\b/i, reason: 'Public package or release publish' },
  { re: /\b(chmod\s+777|chown\s+-R|mkfs|dd\s+if=|kill\s+-9)\b/i, reason: 'High-impact system/filesystem operation' },
  { re: /\b(curl|wget)\b.*\|\s*(sh|bash|zsh|python|node)\b/i, reason: 'Remote script pipe execution' }
];

const SHELL_TOOLS = new Set(['run_shell_command', 'Bash', 'shell', 'execute_command', 'beforeShellExecution']);
const READ_TOOLS = new Set(['read_file', 'Read', 'Glob', 'Grep', 'LS', 'list_dir', 'search_files']);

export function classifyToolRisk(toolName, toolInput = {}) {
  const inputObj = toolInput && typeof toolInput === 'object' ? toolInput : {};
  const commandStr =
    inputObj.command ||
    inputObj.cmd ||
    (typeof toolInput === 'string' ? toolInput : '');

  const filePath =
    inputObj.file_path ||
    inputObj.path ||
    inputObj.target_file ||
    '';

  // Check self-tampering / secrets FIRST — even read_file or `cat` on secrets/config is high risk!
  if ((filePath && SELF_TAMPER_OR_SECRET_RE.test(filePath)) || (commandStr && SELF_TAMPER_OR_SECRET_RE.test(commandStr))) {
    return {
      risk: 'high',
      safeReadOnly: false,
      reason: 'Targets Pushgate/agent security config, credentials, or secrets'
    };
  }

  if (READ_TOOLS.has(toolName)) {
    return { risk: 'low', safeReadOnly: true, reason: 'Read-only inspection tool' };
  }

  if (commandStr) {
    for (const item of HIGH_RISK_PATTERNS) {
      if (item.re.test(commandStr)) {
        return { risk: 'high', safeReadOnly: false, reason: item.reason };
      }
    }

    if (
      SHELL_TOOLS.has(toolName) &&
      !SHELL_UNSAFE_METACHARS_RE.test(commandStr) &&
      SAFE_READ_ONLY_SHELL_RE.test(commandStr)
    ) {
      return { risk: 'low', safeReadOnly: true, reason: 'Read-only shell command' };
    }
  }

  return { risk: 'medium', safeReadOnly: false, reason: 'Standard mutating or external tool call' };
}

/**
 * Evaluates configured routing/policy rules AND gate mode.
 *
 * Returns:
 *   { action: 'pass' | 'allow' | 'deny' | 'gate', risk, reason, routeTopic?, ruleName? }
 */
export function evaluateGatePolicy(config, { toolName, toolInput = {}, projectName = '', idleSecs = Infinity }) {
  if (!config || !config.topic || config.mode === 'off' || config.mode === 'notify-only') {
    return { action: 'pass', risk: 'low', reason: 'Gate inactive in current mode' };
  }

  const inputObj = toolInput && typeof toolInput === 'object' ? toolInput : {};
  const riskInfo = classifyToolRisk(toolName, toolInput);
  const haystack = `${projectName} ${toolName} ${inputObj.command || ''} ${inputObj.file_path || inputObj.path || ''} ${JSON.stringify(toolInput)}`;

  // 1. Self-tamper / secret protection cannot be auto-allowed unless an explicit rule overrides,
  //    evaluate explicit custom / team routing rules first (first match wins)
  if (Array.isArray(config.rules)) {
    for (const rule of config.rules) {
      if (!rule?.match) continue;
      try {
        const re = new RegExp(rule.match, 'i');
        if (re.test(haystack)) {
          if (rule.action === 'allow') {
            return {
              action: 'allow',
              risk: riskInfo.risk,
              reason: rule.reason || `Auto-allowed by policy rule "${rule.name || rule.match}"`,
              ruleName: rule.name || rule.match
            };
          }
          if (rule.action === 'deny') {
            return {
              action: 'deny',
              risk: 'high',
              reason: rule.reason || `Blocked by policy rule "${rule.name || rule.match}"`,
              ruleName: rule.name || rule.match
            };
          }
          return {
            action: 'gate',
            risk: rule.risk || riskInfo.risk,
            reason: rule.reason || riskInfo.reason,
            routeTopic: rule.topic || config.topic,
            approverLabel: rule.approver || null,
            ruleName: rule.name || rule.match
          };
        }
      } catch {
        // Ignore invalid user regex
      }
    }
  }

  const awayThreshold = config.awayThresholdSec ?? 60;
  const isAway = idleSecs >= awayThreshold;

  // 2. Mode-based evaluation
  if (config.mode === 'smart') {
    if (riskInfo.safeReadOnly && riskInfo.risk === 'low') {
      return {
        action: 'allow',
        risk: 'low',
        reason: riskInfo.reason
      };
    }
    if (riskInfo.risk === 'high') {
      return {
        action: 'gate',
        risk: 'high',
        reason: riskInfo.reason,
        routeTopic: config.topic
      };
    }
    if (!isAway) {
      return {
        action: 'pass',
        risk: 'medium',
        reason: `User active (${idleSecs}s idle) and medium risk`
      };
    }
    return {
      action: 'gate',
      risk: 'medium',
      reason: riskInfo.reason,
      routeTopic: config.topic
    };
  }

  if (config.mode === 'away') {
    if (!isAway) {
      return {
        action: 'pass',
        risk: riskInfo.risk,
        reason: `User active (${idleSecs}s idle)`
      };
    }
    return {
      action: 'gate',
      risk: riskInfo.risk,
      reason: riskInfo.reason,
      routeTopic: config.topic
    };
  }

  // Default: mode === 'always'
  return {
    action: 'gate',
    risk: riskInfo.risk,
    reason: riskInfo.reason,
    routeTopic: config.topic
  };
}
