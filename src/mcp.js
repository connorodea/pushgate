import path from 'node:path';
import { loadConfig, appendAuditLog } from './config.js';
import { sendAlert, requestMobileApproval, requestMobileChoice } from './ntfy.js';
import { classifyToolRisk } from './policy.js';

const MCP_TOOLS = [
  {
    name: 'pushgate_notify',
    description:
      'Send an instant push notification to the developer\'s phone lock screen and/or desktop banner (use when finishing long tasks, builds, deployments, or encountering critical errors).',
    inputSchema: {
      type: 'object',
      properties: {
        title: {
          type: 'string',
          description: 'Short notification headline'
        },
        message: {
          type: 'string',
          description: 'Concise details or summary'
        },
        level: {
          type: 'string',
          enum: ['info', 'success', 'warning', 'error'],
          description: 'Severity level controlling priority and icon tags'
        }
      },
      required: ['title', 'message']
    }
  },
  {
    name: 'pushgate_ask',
    description:
      'Ask the developer a yes/no or multiple-choice question on their mobile lock screen and Pushgate dashboard, blocking until they tap a response.',
    inputSchema: {
      type: 'object',
      properties: {
        question: {
          type: 'string',
          description: 'Clear question to ask the developer'
        },
        options: {
          type: 'array',
          items: { type: 'string' },
          description: 'Choices presented as action buttons (defaults to ["Yes", "No"]; first 3 appear directly on mobile lock screen)'
        },
        title: {
          type: 'string',
          description: 'Optional notification title'
        }
      },
      required: ['question']
    }
  },
  {
    name: 'pushgate_gate',
    description:
      'Request explicit cryptographic approval from the developer\'s mobile lock screen or Pushgate dashboard before performing a sensitive or irreversible action.',
    inputSchema: {
      type: 'object',
      properties: {
        action: {
          type: 'string',
          description: 'Human-readable description of the sensitive operation'
        },
        command: {
          type: 'string',
          description: 'Optional exact shell command, SQL query, or target resource'
        },
        risk: {
          type: 'string',
          enum: ['low', 'medium', 'high'],
          description: 'Optional risk override'
        }
      },
      required: ['action']
    }
  }
];

function levelMeta(level = 'info') {
  switch (level) {
    case 'success':
      return { tags: ['white_check_mark', 'sparkles'], priority: 3 };
    case 'warning':
      return { tags: ['warning'], priority: 4 };
    case 'error':
      return { tags: ['rotating_light', 'x'], priority: 5 };
    default:
      return { tags: ['bell', 'robot'], priority: 3 };
  }
}

async function handleToolCall(name, args = {}) {
  const config = loadConfig();
  const project = path.basename(process.cwd()) || 'workspace';

  if (!config || (!config.topic && !config.bell)) {
    return {
      isError: true,
      content: [
        {
          type: 'text',
          text: 'Pushgate is not configured yet. Ask the user to run `pushgate setup` in their terminal.'
        }
      ]
    };
  }

  if (name === 'pushgate_notify') {
    const meta = levelMeta(args.level);
    await sendAlert(config, {
      title: args.title || `Agent Update [${project}]`,
      message: args.message || '',
      tags: meta.tags,
      priority: meta.priority
    });
    appendAuditLog({
      event: 'McpNotify',
      agent: 'mcp',
      project,
      tool: 'pushgate_notify',
      decision: 'SENT'
    });
    return {
      content: [
        {
          type: 'text',
          text: `Notification delivered: "${args.title}"`
        }
      ]
    };
  }

  if (!config.topic) {
    return {
      isError: true,
      content: [
        {
          type: 'text',
          text: 'Pushgate mobile topic is not configured. Run `pushgate setup` to enable interactive approvals and questions.'
        }
      ]
    };
  }

  if (name === 'pushgate_ask') {
    const startedAt = Date.now();
    const options = Array.isArray(args.options) && args.options.length > 0 ? args.options : ['Yes', 'No'];
    const result = await requestMobileChoice(config, {
      title: args.title || `Agent question [${project}]`,
      question: String(args.question || 'Agent needs your input'),
      options,
      agent: 'mcp',
      project
    });

    appendAuditLog({
      event: 'McpAsk',
      agent: 'mcp',
      project,
      tool: 'pushgate_ask',
      command: String(args.question || '').slice(0, 160),
      decision: result.decision === 'ANSWERED' ? `ANSWER:${result.choice}` : 'TIMEOUT',
      source: result.source || 'mobile',
      latencyMs: Date.now() - startedAt
    });

    if (result.decision === 'ANSWERED') {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              answered: true,
              choice: result.choice,
              index: result.index,
              source: result.source
            })
          }
        ]
      };
    }

    return {
      isError: true,
      content: [
        {
          type: 'text',
          text: `Developer did not respond within ${config.timeoutSec} seconds.`
        }
      ]
    };
  }

  if (name === 'pushgate_gate') {
    const startedAt = Date.now();
    const inferred = classifyToolRisk('run_shell_command', { command: args.command || args.action });
    const risk = ['low', 'medium', 'high'].includes(args.risk) ? args.risk : inferred.risk;
    const body = args.command ? `${args.action}\n\n${args.command}` : String(args.action || '');

    const result = await requestMobileApproval(config, {
      title: `Approval needed [${project}]`,
      body,
      agent: 'mcp',
      project,
      tool: 'pushgate_gate',
      risk
    });

    appendAuditLog({
      event: 'McpGate',
      agent: 'mcp',
      project,
      tool: 'pushgate_gate',
      command: String(args.command || args.action || '').slice(0, 160),
      risk,
      decision: result.decision,
      source: result.source || 'mobile',
      latencyMs: Date.now() - startedAt
    });

    if (result.decision === 'ALLOW') {
      return {
        content: [
          {
            type: 'text',
            text: JSON.stringify({
              approved: true,
              decision: 'ALLOW',
              source: result.source
            })
          }
        ]
      };
    }

    return {
      isError: true,
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            approved: false,
            decision: result.decision,
            source: result.source,
            reason:
              result.decision === 'DENY'
                ? 'Developer explicitly denied this action.'
                : `Approval timed out after ${config.timeoutSec} seconds.`
          })
        }
      ]
    };
  }

  throw new Error(`Unknown tool: ${name}`);
}

export async function handleJsonRpcMessage(msg) {
  if (!msg || typeof msg !== 'object') return null;

  if (msg.id === undefined || msg.id === null) {
    return null;
  }

  const { id, method, params } = msg;

  try {
    if (method === 'initialize') {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          protocolVersion: params?.protocolVersion || '2024-11-05',
          capabilities: {
            tools: {}
          },
          serverInfo: {
            name: 'pushgate',
            version: '1.0.0'
          }
        }
      };
    }

    if (method === 'ping') {
      return { jsonrpc: '2.0', id, result: {} };
    }

    if (method === 'tools/list') {
      return {
        jsonrpc: '2.0',
        id,
        result: {
          tools: MCP_TOOLS
        }
      };
    }

    if (method === 'tools/call') {
      const toolResult = await handleToolCall(params?.name, params?.arguments || {});
      return {
        jsonrpc: '2.0',
        id,
        result: toolResult
      };
    }

    return {
      jsonrpc: '2.0',
      id,
      error: {
        code: -32601,
        message: `Method not found: ${method}`
      }
    };
  } catch (err) {
    return {
      jsonrpc: '2.0',
      id,
      error: {
        code: -32000,
        message: err.message || 'Internal MCP server error'
      }
    };
  }
}

export function runMcpServer() {
  let framingMode = null; // 'line' | 'content-length'
  let rawBuffer = Buffer.alloc(0);
  let draining = false;

  function sendResponse(obj) {
    if (!obj) return;
    const json = JSON.stringify(obj);
    if (framingMode === 'content-length') {
      const byteLen = Buffer.byteLength(json, 'utf-8');
      process.stdout.write(`Content-Length: ${byteLen}\r\n\r\n${json}`);
    } else {
      process.stdout.write(`${json}\n`);
    }
  }

  function extractNextMessage() {
    if (!framingMode && rawBuffer.length > 0) {
      const preview = rawBuffer.subarray(0, 48).toString('utf-8').trimStart();
      if (!preview) return null;
      framingMode = /^Content-Length:/i.test(preview) ? 'content-length' : 'line';
    }

    if (framingMode === 'content-length') {
      const headerEnd = rawBuffer.indexOf('\r\n\r\n');
      if (headerEnd === -1) return null;
      const headerStr = rawBuffer.subarray(0, headerEnd).toString('utf-8');
      const match = headerStr.match(/Content-Length:\s*(\d+)/i);
      if (!match) {
        rawBuffer = rawBuffer.subarray(headerEnd + 4);
        return '';
      }
      const contentLen = Number.parseInt(match[1], 10);
      const totalLen = headerEnd + 4 + contentLen;
      if (rawBuffer.length < totalLen) return null;
      const bodyStr = rawBuffer.subarray(headerEnd + 4, totalLen).toString('utf-8');
      rawBuffer = rawBuffer.subarray(totalLen);
      return bodyStr;
    }

    if (framingMode === 'line') {
      const nl = rawBuffer.indexOf('\n');
      if (nl === -1) return null;
      const lineStr = rawBuffer.subarray(0, nl).toString('utf-8');
      rawBuffer = rawBuffer.subarray(nl + 1);
      return lineStr;
    }

    return null;
  }

  async function drainBuffer() {
    if (draining) return;
    draining = true;
    try {
      while (true) {
        const nextStr = extractNextMessage();
        if (nextStr === null) break;
        if (!nextStr.trim()) continue;
        let parsed;
        try {
          parsed = JSON.parse(nextStr);
        } catch {
          continue;
        }
        const res = await handleJsonRpcMessage(parsed);
        if (res) sendResponse(res);
      }
    } finally {
      draining = false;
    }
  }

  process.stdin.on('data', chunk => {
    rawBuffer = Buffer.concat([rawBuffer, Buffer.from(chunk)]);
    drainBuffer().catch(err => {
      process.stderr.write(`[pushgate-mcp] Drain error: ${err.message}\n`);
    });
  });

  process.stdin.resume();
}
