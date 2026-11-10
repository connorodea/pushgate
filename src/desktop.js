import { spawnSync } from 'node:child_process';
import os from 'node:os';

export function ringDesktopAlert({ title, message, sound = true }) {
  // Emit terminal bell to stderr so stdout JSON hook streams remain clean
  try {
    process.stderr.write('\x07');
  } catch {
    // Ignore
  }

  if (process.env.PUSHGATE_DISABLE_DESKTOP_EXEC === '1') {
    return true;
  }

  const cleanTitle = String(title || 'Pushgate').replace(/[\r\n\t]+/g, ' ').trim().slice(0, 100);
  const cleanMsg = String(message || '').replace(/[\r\n\t]+/g, ' ').trim().slice(0, 220);

  const platform = os.platform();
  try {
    if (platform === 'darwin') {
      const soundClause = sound ? ' sound name "Glass"' : '';
      const script = `on run argv\ndisplay notification (item 2 of argv) with title (item 1 of argv)${soundClause}\nend run`;
      spawnSync('osascript', ['-e', script, cleanTitle, cleanMsg], {
        timeout: 2500,
        stdio: 'ignore'
      });
      return true;
    }

    if (platform === 'linux') {
      spawnSync('notify-send', [cleanTitle, cleanMsg], {
        timeout: 2500,
        stdio: 'ignore'
      });
      return true;
    }
  } catch {
    // Best effort desktop banner
  }
  return false;
}
