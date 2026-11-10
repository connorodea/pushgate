import crypto from 'node:crypto';
import {
  savePendingRequest,
  removePendingRequest,
  readLocalResolution
} from './config.js';
import { ringDesktopAlert } from './desktop.js';

export function safeSigEquals(actual, expected) {
  if (typeof actual !== 'string' || typeof expected !== 'string') return false;
  const a = Buffer.from(actual, 'utf-8');
  const b = Buffer.from(expected, 'utf-8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

export function signDecision(secret, reqId, token) {
  return crypto
    .createHmac('sha256', secret)
    .update(`${reqId}:${token}`)
    .digest('hex')
    .slice(0, 24);
}

function registerSignalCleanup(reqId) {
  const onSignal = sig => {
    removePendingRequest(reqId);
    process.exit(sig === 'SIGINT' ? 130 : 143);
  };
  const sigint = () => onSignal('SIGINT');
  const sigterm = () => onSignal('SIGTERM');
  process.once('SIGINT', sigint);
  process.once('SIGTERM', sigterm);
  return () => {
    process.off('SIGINT', sigint);
    process.off('SIGTERM', sigterm);
  };
}

export async function sendAlert(
  config,
  { title, message, tags = ['sparkles'], priority = 3, topicOverride }
) {
  if (config.bell) {
    ringDesktopAlert({ title, message });
  }

  const targetTopic = topicOverride || config.topic;
  if (!targetTopic) {
    return;
  }

  const baseUrl = config.server.replace(/\/$/, '');
  const payload = {
    topic: targetTopic,
    title,
    message,
    priority,
    tags
  };

  const headers = { 'Content-Type': 'application/json' };
  if (config.authToken) {
    headers['Authorization'] = `Bearer ${config.authToken}`;
  }

  const res = await fetch(baseUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify(payload),
    signal: AbortSignal.timeout(8000)
  });

  if (!res.ok) {
    throw new Error(`Push server returned HTTP ${res.status}`);
  }
}

export async function requestMobileApproval(
  config,
  {
    title,
    body,
    agent = 'gemini',
    project = '',
    tool = '',
    risk = 'medium',
    topicOverride,
    approverLabel = null
  }
) {
  const baseUrl = config.server.replace(/\/$/, '');
  const targetTopic = topicOverride || config.topic;
  const reqId = crypto.randomBytes(6).toString('hex');
  const replyTopic = `${targetTopic}-ack-${reqId}`;

  const approveSig = signDecision(config.secret, reqId, 'ALLOW');
  const denySig = signDecision(config.secret, reqId, 'DENY');
  const replyUrl = `${baseUrl}/${encodeURIComponent(replyTopic)}`;

  const actionHeaders = config.authToken
    ? { Authorization: `Bearer ${config.authToken}` }
    : undefined;

  const pushPayload = {
    topic: targetTopic,
    title,
    message: body,
    priority: risk === 'high' ? 5 : 4,
    tags: risk === 'high' ? ['rotating_light', 'lock'] : ['lock', 'robot'],
    actions: [
      {
        action: 'http',
        label: 'Approve',
        url: replyUrl,
        method: 'POST',
        body: JSON.stringify({ decision: 'ALLOW', sig: approveSig, source: 'mobile' }),
        clear: true,
        ...(actionHeaders ? { headers: actionHeaders } : {})
      },
      {
        action: 'http',
        label: 'Deny',
        url: replyUrl,
        method: 'POST',
        body: JSON.stringify({ decision: 'DENY', sig: denySig, source: 'mobile' }),
        clear: true,
        ...(actionHeaders ? { headers: actionHeaders } : {})
      }
    ]
  };

  if (config.bell) {
    ringDesktopAlert({ title, message: body });
  }

  const timeoutMs = (config.timeoutSec || 300) * 1000;
  savePendingRequest({
    reqId,
    kind: 'approval',
    title,
    body,
    agent,
    project,
    tool,
    risk,
    topic: targetTopic,
    approverLabel,
    replyUrl,
    options: [
      { label: 'Approve', decision: 'ALLOW', sig: approveSig },
      { label: 'Deny', decision: 'DENY', sig: denySig }
    ],
    createdAt: new Date().toISOString(),
    expiresAt: Date.now() + timeoutMs + 5000
  });

  const unregisterSignals = registerSignalCleanup(reqId);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error('TIMEOUT')), timeoutMs);

  const headers = { 'Content-Type': 'application/json' };
  if (config.authToken) {
    headers['Authorization'] = `Bearer ${config.authToken}`;
  }

  const validator = payload => {
    if (payload?.decision === 'ALLOW' && safeSigEquals(payload.sig, approveSig)) {
      return { decision: 'ALLOW', source: payload.source || 'mobile' };
    }
    if (payload?.decision === 'DENY' && safeSigEquals(payload.sig, denySig)) {
      return { decision: 'DENY', source: payload.source || 'mobile' };
    }
    return null;
  };

  try {
    const streamUrl = `${baseUrl}/${encodeURIComponent(replyTopic)}/json?since=all`;
    const streamPromise = listenForValidatedPayload(streamUrl, headers, validator, controller.signal);
    streamPromise.catch(() => {});

    const localPromise = watchLocalResolution(reqId, validator, controller.signal);
    localPromise.catch(() => {});

    const pubRes = await fetch(baseUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(pushPayload),
      signal: controller.signal
    });

    if (!pubRes.ok) {
      throw new Error(`Failed to publish gate push: HTTP ${pubRes.status}`);
    }

    return await Promise.race([streamPromise, localPromise]);
  } catch (err) {
    if (controller.signal.aborted && controller.signal.reason?.message === 'TIMEOUT') {
      return { decision: 'TIMEOUT', source: 'timeout' };
    }
    throw err;
  } finally {
    clearTimeout(timer);
    controller.abort();
    unregisterSignals();
    removePendingRequest(reqId);
  }
}

export async function requestMobileChoice(
  config,
  {
    title,
    question,
    options = ['Yes', 'No'],
    agent = 'mcp',
    project = '',
    topicOverride
  }
) {
  const rawOptions = Array.isArray(options) && options.length > 0 ? options : ['Yes', 'No'];
  const filtered = rawOptions.map(o => String(o).trim()).filter(Boolean);
  const cleanOptions = filtered.length > 0 ? filtered : ['Yes', 'No'];

  const baseUrl = config.server.replace(/\/$/, '');
  const targetTopic = topicOverride || config.topic;
  const reqId = crypto.randomBytes(6).toString('hex');
  const replyTopic = `${targetTopic}-ack-${reqId}`;
  const replyUrl = `${baseUrl}/${encodeURIComponent(replyTopic)}`;

  const signedOptions = cleanOptions.map((label, index) => ({
    index,
    label,
    decision: `CHOICE_${index}`,
    sig: signDecision(config.secret, reqId, `CHOICE:${index}`)
  }));

  const actionHeaders = config.authToken
    ? { Authorization: `Bearer ${config.authToken}` }
    : undefined;

  const lockScreenButtons = signedOptions.slice(0, 3).map(opt => ({
    action: 'http',
    label: Array.from(opt.label).slice(0, 28).join(''),
    url: replyUrl,
    method: 'POST',
    body: JSON.stringify({ index: opt.index, sig: opt.sig, source: 'mobile' }),
    clear: true,
    ...(actionHeaders ? { headers: actionHeaders } : {})
  }));

  const extraHint =
    signedOptions.length > 3
      ? `\n(More options in Pushgate Dashboard: ${signedOptions.slice(3).map(o => o.label).join(', ')})`
      : '';

  const pushPayload = {
    topic: targetTopic,
    title,
    message: `${question}${extraHint}`,
    priority: 5,
    tags: ['question', 'robot'],
    actions: lockScreenButtons
  };

  if (config.bell) {
    ringDesktopAlert({ title, message: question });
  }

  const timeoutMs = (config.timeoutSec || 300) * 1000;
  savePendingRequest({
    reqId,
    kind: 'question',
    title,
    body: question,
    agent,
    project,
    tool: 'ask',
    risk: 'medium',
    topic: targetTopic,
    replyUrl,
    options: signedOptions,
    createdAt: new Date().toISOString(),
    expiresAt: Date.now() + timeoutMs + 5000
  });

  const unregisterSignals = registerSignalCleanup(reqId);
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error('TIMEOUT')), timeoutMs);

  const headers = { 'Content-Type': 'application/json' };
  if (config.authToken) {
    headers['Authorization'] = `Bearer ${config.authToken}`;
  }

  const validator = payload => {
    if (typeof payload?.index === 'number') {
      const target = signedOptions[payload.index];
      if (target && safeSigEquals(payload.sig, target.sig)) {
        return {
          decision: 'ANSWERED',
          index: target.index,
          choice: target.label,
          source: payload.source || 'mobile'
        };
      }
    }
    if (typeof payload?.freeText === 'string' && payload.freeText.trim()) {
      const freeSig = signDecision(config.secret, reqId, 'FREETEXT');
      if (safeSigEquals(payload.sig, freeSig)) {
        return {
          decision: 'ANSWERED',
          index: -1,
          choice: payload.freeText.trim(),
          source: payload.source || 'dashboard'
        };
      }
    }
    return null;
  };

  try {
    const streamUrl = `${baseUrl}/${encodeURIComponent(replyTopic)}/json?since=all`;
    const streamPromise = listenForValidatedPayload(streamUrl, headers, validator, controller.signal);
    streamPromise.catch(() => {});

    const localPromise = watchLocalResolution(reqId, validator, controller.signal);
    localPromise.catch(() => {});

    const pubRes = await fetch(baseUrl, {
      method: 'POST',
      headers,
      body: JSON.stringify(pushPayload),
      signal: controller.signal
    });

    if (!pubRes.ok) {
      throw new Error(`Failed to publish question push: HTTP ${pubRes.status}`);
    }

    return await Promise.race([streamPromise, localPromise]);
  } catch (err) {
    if (controller.signal.aborted && controller.signal.reason?.message === 'TIMEOUT') {
      return { decision: 'TIMEOUT', source: 'timeout' };
    }
    throw err;
  } finally {
    clearTimeout(timer);
    controller.abort();
    unregisterSignals();
    removePendingRequest(reqId);
  }
}

function watchLocalResolution(reqId, validator, signal) {
  return new Promise((resolve, reject) => {
    if (signal.aborted) {
      return reject(signal.reason || new Error('Aborted'));
    }

    const interval = setInterval(() => {
      const local = readLocalResolution(reqId);
      if (!local) return;
      const matched = validator(local);
      if (matched) {
        clearInterval(interval);
        resolve(matched);
      }
    }, 150);
    interval.unref?.();

    signal.addEventListener(
      'abort',
      () => {
        clearInterval(interval);
        reject(signal.reason || new Error('Aborted'));
      },
      { once: true }
    );
  });
}

function abortableDelay(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(signal.reason || new Error('Aborted'));
    const t = setTimeout(resolve, ms);
    t.unref?.();
    signal.addEventListener(
      'abort',
      () => {
        clearTimeout(t);
        reject(signal.reason || new Error('Aborted'));
      },
      { once: true }
    );
  });
}

async function listenForValidatedPayload(streamUrl, headers, validator, signal) {
  let attempt = 0;

  while (!signal.aborted) {
    attempt += 1;
    let res;
    try {
      res = await fetch(streamUrl, {
        method: 'GET',
        headers,
        signal
      });
    } catch (err) {
      if (signal.aborted || attempt === 1) throw err;
      await abortableDelay(400, signal);
      continue;
    }

    if (!res.ok || !res.body) {
      if (attempt === 1) {
        throw new Error(`Failed to subscribe to response stream: HTTP ${res.status}`);
      }
      await abortableDelay(400, signal);
      continue;
    }

    const decoder = new TextDecoder();
    let buffer = '';

    try {
      for await (const chunk of res.body) {
        buffer += decoder.decode(chunk, { stream: true });
        const lines = buffer.split('\n');
        buffer = lines.pop() || '';

        for (const line of lines) {
          if (!line.trim()) continue;
          try {
            const event = JSON.parse(line);
            if (event.event !== 'message' || !event.message) continue;

            const payload = JSON.parse(event.message);
            const matched = validator(payload);
            if (matched) {
              return matched;
            }
          } catch {
            // Ignore keepalive frames or malformed payloads
          }
        }
      }
    } catch (err) {
      if (signal.aborted) throw err;
      // Transient mid-stream disconnect: reconnect with ?since=all
    }

    if (!signal.aborted) {
      await abortableDelay(300, signal);
    }
  }

  return { decision: 'TIMEOUT', source: 'timeout' };
}
