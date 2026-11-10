#!/usr/bin/env node

import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = path.resolve(__dirname, '..');
const DEFAULT_CHANGELOG_PATH = path.join(ROOT_DIR, 'CHANGELOG.md');
const PACKAGE_JSON_PATH = path.join(ROOT_DIR, 'package.json');
const BIN_PATH = path.join(ROOT_DIR, 'bin', 'pushgate.js');

const SECTION_TITLES = {
  added: 'Added',
  changed: 'Changed',
  fixed: 'Fixed',
  security: 'Security',
  removed: 'Removed',
  deprecated: 'Deprecated'
};

export function addUnreleasedEntry(changelogPath, categoryKey, text) {
  const sectionTitle = SECTION_TITLES[String(categoryKey || '').toLowerCase()];
  if (!sectionTitle) {
    throw new Error(
      `Invalid category "${categoryKey}". Choose one of: ${Object.keys(SECTION_TITLES).join(', ')}`
    );
  }
  const cleanText = String(text || '').trim();
  if (!cleanText) {
    throw new Error('Changelog entry text cannot be empty.');
  }

  const raw = fs.readFileSync(changelogPath, 'utf-8');
  const unreleasedIdx = raw.indexOf('## [Unreleased]');
  if (unreleasedIdx === -1) {
    throw new Error('Could not find "## [Unreleased]" section in CHANGELOG.md');
  }

  const afterHeaderIdx = raw.indexOf('\n', unreleasedIdx) + 1;
  const nextReleaseMatch = raw.slice(afterHeaderIdx).match(/\n---\n+\s*## \[/);
  const blockEndIdx = nextReleaseMatch
    ? afterHeaderIdx + nextReleaseMatch.index
    : raw.length;

  let unreleasedBody = raw.slice(afterHeaderIdx, blockEndIdx);
  const bullet = `- ${cleanText}`;

  if (unreleasedBody.includes(bullet)) {
    return false; // Already recorded
  }

  const heading = `### ${sectionTitle}`;
  const headingIdx = unreleasedBody.indexOf(heading);

  if (headingIdx !== -1) {
    const insertPos = unreleasedBody.indexOf('\n', headingIdx) + 1;
    const prefix = unreleasedBody.slice(0, insertPos);
    const suffix = unreleasedBody.slice(insertPos).replace(/^\n*/, '\n');
    unreleasedBody = `${prefix}\n${bullet}${suffix}`;
  } else {
    const trimmed = unreleasedBody.trimEnd();
    unreleasedBody = `${trimmed ? trimmed + '\n\n' : '\n'}${heading}\n\n${bullet}\n`;
  }

  const updated = raw.slice(0, afterHeaderIdx) + unreleasedBody + raw.slice(blockEndIdx);
  fs.writeFileSync(changelogPath, updated);
  return true;
}

export function promoteUnreleasedToVersion(changelogPath, newVersion, releaseDate) {
  if (!/^\d+\.\d+\.\d+(-[a-zA-Z0-9.-]+)?$/.test(newVersion)) {
    throw new Error(`Invalid SemVer "${newVersion}" (expected e.g. 1.1.0)`);
  }
  const dateStr = releaseDate || new Date().toISOString().slice(0, 10);
  const raw = fs.readFileSync(changelogPath, 'utf-8');

  const unreleasedHeader = '## [Unreleased]';
  const unreleasedIdx = raw.indexOf(unreleasedHeader);
  if (unreleasedIdx === -1) {
    throw new Error('Could not find "## [Unreleased]" section in CHANGELOG.md');
  }

  const afterHeaderIdx = raw.indexOf('\n', unreleasedIdx) + 1;
  const sepMatch = raw.slice(afterHeaderIdx).match(/\n---\n+\s*## \[([^\]]+)\]/);
  const blockEndIdx = sepMatch ? afterHeaderIdx + sepMatch.index : raw.length;
  const prevVersion = sepMatch ? sepMatch[1] : null;

  const unreleasedContent = raw.slice(afterHeaderIdx, blockEndIdx).trim();
  if (!unreleasedContent) {
    throw new Error('"[Unreleased]" has no entries to release yet.');
  }

  const replacement = `\n---\n\n## [${newVersion}] - ${dateStr}\n\n${unreleasedContent}\n`;
  let updated = raw.slice(0, afterHeaderIdx) + replacement + raw.slice(blockEndIdx);

  // Update footer comparison links if present
  if (prevVersion && updated.includes('[Unreleased]:')) {
    updated = updated.replace(
      /\[Unreleased\]:\s*(https:\/\/github\.com\/[^\s]+)\/compare\/v[^\s]+\.\.\.HEAD/,
      `[Unreleased]: $1/compare/v${newVersion}...HEAD\n[${newVersion}]: $1/compare/v${prevVersion}...v${newVersion}`
    );
  }

  fs.writeFileSync(changelogPath, updated);
  return { version: newVersion, date: dateStr };
}

function inferCategoryFromSubject(subject) {
  const s = subject.toLowerCase();
  if (s.startsWith('sec:') || s.startsWith('security')) return 'security';
  if (s.startsWith('fix:') || s.startsWith('fix(')) return 'fixed';
  if (s.startsWith('feat:') || s.startsWith('feat(')) return 'added';
  return 'changed';
}

function syncGitCommits(changelogPath) {
  const existing = fs.readFileSync(changelogPath, 'utf-8');
  const out = execFileSync(
    'git',
    ['log', '--pretty=format:%h|%s', '-n', '30'],
    { cwd: ROOT_DIR, encoding: 'utf-8' }
  ).trim();

  if (!out) return 0;
  let addedCount = 0;
  for (const line of out.split('\n').reverse()) {
    const [hash, ...rest] = line.split('|');
    const subject = rest.join('|').trim();
    if (!hash || !subject || subject.startsWith('chore(release):')) continue;
    if (existing.includes(`(\`${hash}\`)`) || existing.includes(subject)) continue;
    const category = inferCategoryFromSubject(subject);
    if (addUnreleasedEntry(changelogPath, category, `${subject} (\`${hash}\`)`)) {
      addedCount += 1;
    }
  }
  return addedCount;
}

function printSummary(changelogPath) {
  const raw = fs.readFileSync(changelogPath, 'utf-8');
  const lines = raw.split('\n').slice(0, 48).join('\n');
  console.log(lines);
}

// CLI execution when invoked directly
if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const cliArgs = process.argv.slice(2);
  const customFileIdx = cliArgs.indexOf('--file');
  const targetFile =
    customFileIdx !== -1 && cliArgs[customFileIdx + 1]
      ? path.resolve(cliArgs[customFileIdx + 1])
      : DEFAULT_CHANGELOG_PATH;

  if (cliArgs.includes('--add')) {
    const idx = cliArgs.indexOf('--add');
    const cat = cliArgs[idx + 1];
    const msg = cliArgs[idx + 2];
    const inserted = addUnreleasedEntry(targetFile, cat, msg);
    console.log(inserted ? `✅ Added [${cat}] entry to ${targetFile}` : 'ℹ️ Entry already present.');
  } else if (cliArgs.includes('--sync-git')) {
    const count = syncGitCommits(targetFile);
    console.log(`✅ Synced ${count} new git commit(s) into [Unreleased].`);
  } else if (cliArgs.includes('--release')) {
    const idx = cliArgs.indexOf('--release');
    const ver = cliArgs[idx + 1];
    const info = promoteUnreleasedToVersion(targetFile, ver);
    if (targetFile === DEFAULT_CHANGELOG_PATH) {
      const pkg = JSON.parse(fs.readFileSync(PACKAGE_JSON_PATH, 'utf-8'));
      pkg.version = ver;
      fs.writeFileSync(PACKAGE_JSON_PATH, JSON.stringify(pkg, null, 2) + '\n');
      const binRaw = fs.readFileSync(BIN_PATH, 'utf-8');
      fs.writeFileSync(
        BIN_PATH,
        binRaw.replace(/const VERSION = '[^']+';/, `const VERSION = '${ver}';`)
      );
    }
    console.log(`🎉 Released v${info.version} (${info.date}) in CHANGELOG.md!`);
  } else {
    printSummary(targetFile);
  }
}
