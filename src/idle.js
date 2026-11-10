import { execSync } from 'node:child_process';
import os from 'node:os';

export function getSystemIdleSeconds() {
  if (process.env.PUSHGATE_IDLE_SECONDS !== undefined) {
    const override = Number(process.env.PUSHGATE_IDLE_SECONDS);
    return Number.isNaN(override) ? Infinity : override;
  }

  const platform = os.platform();
  try {
    if (platform === 'darwin') {
      const out = execSync("ioreg -c IOHIDSystem | awk '/HIDIdleTime/ {print int($NF/1000000000); exit}'", {
        encoding: 'utf-8',
        timeout: 1500,
        stdio: ['ignore', 'pipe', 'ignore']
      }).trim();
      const secs = Number.parseInt(out, 10);
      return Number.isNaN(secs) ? Infinity : secs;
    }

    if (platform === 'linux') {
      const out = execSync('xprintidle', {
        encoding: 'utf-8',
        timeout: 1500,
        stdio: ['ignore', 'pipe', 'ignore']
      }).trim();
      const ms = Number.parseInt(out, 10);
      return Number.isNaN(ms) ? Infinity : Math.floor(ms / 1000);
    }
  } catch {
    // Fallback: treat as away so security gates still trigger
  }
  return Infinity;
}
