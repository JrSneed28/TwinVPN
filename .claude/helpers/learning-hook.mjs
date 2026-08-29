#!/usr/bin/env node
/**
 * Learning hook adapter — connects learning-service.mjs to Claude Code hooks.
 *
 * learning-service.mjs ships with no caller: nothing writes its patterns.db, so
 * .claude-flow/learning/ never existed and ReasoningBank stayed empty. This is
 * the missing plumbing. It reads the session transcript Claude Code hands every
 * hook, so it costs nothing per tool call — one process per turn end.
 *
 *   recall       UserPromptSubmit  search past turns, print them, record usage
 *   capture      Stop              distil the turn into a pattern + trajectory
 *   consolidate  SessionEnd        prune/dedup, write learning-metrics.json
 *   stats                          manual inspection
 *
 * Embeddings come from @huggingface/transformers (MiniLM, ~230ms warm). The
 * service's own embedder falls back to hash vectors when the agentic-flow ONNX
 * model is absent; mixing the two in one index makes every distance
 * meaningless, so a provider change stops the run instead of poisoning the DB
 * (LEARNING_HOOK_ALLOW_HASH=1 to accept hash vectors anyway).
 */

import { closeSync, openSync, readSync, statSync, writeFileSync } from 'fs';
import { dirname, join, relative } from 'path';
import { fileURLToPath } from 'url';
import { LearningService } from './learning-service.mjs';

const HELPERS_DIR = dirname(fileURLToPath(import.meta.url));
const PROJECT_ROOT = join(HELPERS_DIR, '../..');
const METRICS_PATH = join(PROJECT_ROOT, '.claude-flow/learning/learning-metrics.json');
const MODEL = 'Xenova/all-MiniLM-L6-v2';
const PROVIDER = `transformers:${MODEL}`;
const RECALL_FLOOR = Number(process.env.LEARNING_HOOK_FLOOR || 0.30);
const MAX_STRATEGY = 480;

// Hooks must never hang or fail the turn.
const GUARD_MS = Number(process.env.LEARNING_HOOK_GUARD_MS || 15000);
const guard = setTimeout(() => process.exit(0), GUARD_MS);
guard.unref();

// ── stdin ────────────────────────────────────────────────────────────────────

async function readStdin() {
  if (process.stdin.isTTY) return '';
  return new Promise((resolve) => {
    let data = '';
    const timer = setTimeout(() => { process.stdin.pause(); resolve(data); }, 500);
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (c) => { data += c; });
    process.stdin.on('end', () => { clearTimeout(timer); resolve(data); });
    process.stdin.on('error', () => { clearTimeout(timer); resolve(data); });
    process.stdin.resume();
  });
}

// ── service ──────────────────────────────────────────────────────────────────

// The service narrates on stdout — its embedder choice, every promotion. On
// UserPromptSubmit that lands in the model's context, so console.log is muted
// for the whole process and everything we mean to say goes through
// process.stdout.write.
console.log = () => {};

async function embedder() {
  const T = await import('@huggingface/transformers');
  const pipe = await T.pipeline('feature-extraction', MODEL, { dtype: 'fp32' });
  return async (text) => {
    const out = await pipe(String(text).slice(0, 500), { pooling: 'mean', normalize: true });
    return new Float32Array(out.data);
  };
}

async function open(sessionId) {
  const service = new LearningService();
  await service.initialize(sessionId);
  service.db.pragma('journal_mode = WAL');
  service.db.pragma('busy_timeout = 4000');

  let provider = PROVIDER;
  try {
    const embed = await embedder();
    service.embeddingService.embed = embed;
  } catch (e) {
    if (process.env.LEARNING_HOOK_ALLOW_HASH !== '1') {
      service.close();
      process.stderr.write(`[learning] ${MODEL} unavailable (${e.message}); skipping\n`);
      return null;
    }
    provider = 'hash';
  }

  const stored = service._getState('embedding_provider');
  if (!stored) service._setState('embedding_provider', provider);
  else if (stored !== provider) {
    service.close();
    process.stderr.write(
      `[learning] patterns.db was built with ${stored}, this run has ${provider}; ` +
      `vectors are not comparable. Delete .claude-flow/learning/patterns.db to rebuild.\n`);
    return null;
  }
  return service;
}

// ── transcript ───────────────────────────────────────────────────────────────

/** Read the bytes appended since `from`; returns whole lines only. */
function readSince(path, from) {
  const size = statSync(path).size;
  const start = from > size ? 0 : from;       // transcript replaced or truncated
  if (size === start) return { lines: [], cursor: size };
  const fd = openSync(path, 'r');
  const buf = Buffer.allocUnsafe(size - start);
  readSync(fd, buf, 0, buf.length, start);
  closeSync(fd);
  const text = buf.toString('utf8');
  const end = text.lastIndexOf('\n');
  if (end < 0) return { lines: [], cursor: start };
  return {
    lines: text.slice(0, end).split('\n').filter(Boolean),
    cursor: start + Buffer.byteLength(text.slice(0, end + 1)),
  };
}

// Machine-authored text that arrives wearing a user record: slash-command
// expansions, hook output, system reminders, background-task notifications.
// None of it is a request, and a turn keyed on one recalls nothing useful.
const INJECTED = /^\s*<(system-reminder|command-name|command-message|command-args|local-command|task-notification|user-prompt-submit-hook)/;

/** "cd /x && cargo test -p foo" → "cargo test"; env assignments are not the verb. */
function commandHead(command) {
  const words = command.trim().replace(/^cd\s+\S+\s*(&&|;)\s*/, '').split(/\s+/);
  const verb = words.findIndex((w) => !w.includes('=') && !w.startsWith('/') && !w.startsWith('$'));
  if (verb < 0) return '';
  const next = words[verb + 1];
  return next && /^[a-z][\w:-]*$/i.test(next) ? `${words[verb]} ${next}` : words[verb];
}

function userText(content) {
  if (typeof content === 'string') return content;
  if (!Array.isArray(content)) return '';
  return content.filter((b) => b?.type === 'text').map((b) => b.text).join('\n');
}

/**
 * Split records into turns — a turn starts at each real user request. Live, a
 * Stop hook usually hands us one; the first run of an existing session hands us
 * the whole file, and one mega-pattern over fifty requests teaches nothing.
 */
function segment(lines) {
  const turns = [];
  let current = null;
  for (const line of lines) {
    let rec;
    try { rec = JSON.parse(line); } catch { continue; }
    const starts = rec.type === 'user' && !rec.isMeta && !rec.isSidechain &&
      (() => { const t = userText(rec.message?.content).trim(); return t && !INJECTED.test(t); })();
    if (starts || !current) { current = []; turns.push(current); }
    current.push(line);
  }
  return turns.slice(-Number(process.env.LEARNING_HOOK_MAX_TURNS || 20));
}

/** Fold one turn's records into the facts worth remembering. */
function summarize(lines) {
  const turn = {
    request: '', tools: {}, files: [], commands: [], errors: 0, steps: [], fallback: '',
  };
  const seen = new Set();

  for (const line of lines) {
    let rec;
    try { rec = JSON.parse(line); } catch { continue; }

    if (rec.type === 'last-prompt' && typeof rec.lastPrompt === 'string') {
      turn.fallback = rec.lastPrompt;
      continue;
    }

    const content = rec.message?.content;

    if (rec.type === 'user' && !rec.isMeta && !rec.isSidechain) {
      const text = userText(content).trim();
      if (text && !INJECTED.test(text)) turn.request = text;
    }

    if (rec.type === 'user' && Array.isArray(content)) {
      for (const b of content) if (b?.type === 'tool_result' && b.is_error) turn.errors++;
    }

    if (rec.type === 'assistant' && Array.isArray(content)) {
      for (const b of content) {
        if (b?.type !== 'tool_use') continue;
        const name = b.name || 'tool';
        turn.tools[name] = (turn.tools[name] || 0) + 1;
        turn.steps.push(name);
        const input = b.input || {};
        const file = input.file_path || input.notebook_path;
        if (file && !seen.has(file)) { seen.add(file); turn.files.push(file); }
        if (typeof input.command === 'string') {
          const head = commandHead(input.command);
          if (head && !turn.commands.includes(head)) turn.commands.push(head);
        }
      }
    }
  }

  if (!turn.request) turn.request = turn.fallback;
  return turn;
}

const DOMAINS = [
  [/\.rs$|Cargo\.toml$/, 'rust'],
  [/\.tsx?$|\.jsx?$|\.mjs$|\.cjs$/, 'typescript'],
  [/\.py$/, 'python'],
  [/\.md$/, 'docs'],
  [/\.(json|ya?ml|toml)$/, 'config'],
  [/\.sh$/, 'shell'],
];

function domainOf(files) {
  const votes = {};
  for (const f of files) {
    for (const [re, name] of DOMAINS) if (re.test(f)) { votes[name] = (votes[name] || 0) + 1; break; }
  }
  const best = Object.entries(votes).sort((a, b) => b[1] - a[1])[0];
  return best ? best[0] : 'general';
}

/** Heuristic, and deliberately a coarse one: errors cost, a clean verify pays. */
function qualityOf(turn) {
  let q = 0.6 - Math.min(turn.errors, 5) * 0.05;
  const verified = turn.commands.some((c) => /^(cargo|npm|pnpm|yarn|make|pytest|go)\b/.test(c));
  if (verified && turn.errors === 0) q += 0.1;
  return Math.max(0.1, Math.min(0.95, q));
}

function short(path) {
  const rel = relative(PROJECT_ROOT, path);
  return rel && !rel.startsWith('..') ? rel : path;
}

function strategyOf(turn) {
  const parts = [];
  const request = turn.request.replace(/\s+/g, ' ').trim().slice(0, 200);
  parts.push(`Asked to: ${request}`);
  const tools = Object.entries(turn.tools).sort((a, b) => b[1] - a[1])
    .map(([n, c]) => (c > 1 ? `${n}x${c}` : n)).slice(0, 6).join(', ');
  if (tools) parts.push(`tools: ${tools}`);
  if (turn.files.length) parts.push(`files: ${turn.files.slice(0, 6).map(short).join(', ')}`);
  if (turn.commands.length) parts.push(`ran: ${turn.commands.slice(0, 6).join(', ')}`);
  parts.push(turn.errors ? `outcome: ${turn.errors} tool errors` : 'outcome: no tool errors');
  return parts.join('; ').slice(0, MAX_STRATEGY);
}

// ── commands ─────────────────────────────────────────────────────────────────

async function learn(service, turn) {
  // A turn with no request or no tool calls taught nothing worth a vector.
  if (!turn.request || !turn.steps.length) return;

  const now = Date.now();
  const domain = domainOf(turn.files);
  const quality = qualityOf(turn);
  const stored = await service.storePattern(strategyOf(turn), domain, {
    quality,
    source: 'transcript',
    sessionId: service.sessionId,
    files: turn.files.slice(0, 20).map(short),
    tools: turn.tools,
    errors: turn.errors,
  });

  service.db.prepare(`
    INSERT INTO trajectories
    (id, session_id, domain, steps, quality_score, verdict, started_at, ended_at, distilled_pattern_id)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
  `).run(
    `traj_${now}_${Math.random().toString(36).slice(2, 9)}`,
    service.sessionId, domain,
    JSON.stringify({
      steps: turn.steps.slice(0, 200),
      files: turn.files.slice(0, 40).map(short),
      commands: turn.commands.slice(0, 40),
    }),
    quality,
    turn.errors ? 'errors' : 'clean',
    now, now, stored.id,
  );
}

async function capture(input) {
  const path = input.transcript_path || input.transcriptPath;
  if (!path) return;
  let size;
  try { size = statSync(path).size; } catch { return; }

  const sessionId = input.session_id || input.sessionId || null;
  const service = await open(sessionId);
  if (!service) return;

  try {
    const key = `transcript_cursor:${service.sessionId}`;
    const from = Number(service._getState(key) || 0);
    if (from >= size) return;

    const { lines, cursor } = readSince(path, from);
    service._setState(key, String(cursor));
    if (!lines.length) return;

    for (const turn of segment(lines)) await learn(service, summarize(turn));
  } finally {
    service.close();
  }
}

async function recall(input) {
  const prompt = (input.prompt || input.user_prompt || '').trim();
  if (prompt.length < 12) return;

  const service = await open(input.session_id || input.sessionId || null);
  if (!service) return;

  try {
    if (service.shortTermIndex.size() + service.longTermIndex.size() === 0) return;
    const { patterns } = await service.searchPatterns(prompt, 3);
    const hits = patterns.filter((p) => p.similarity >= RECALL_FLOOR && p.strategy);
    if (!hits.length) return;

    const lines = [`[LEARNED] ${hits.length} similar past turn${hits.length > 1 ? 's' : ''}:`];
    for (const h of hits) {
      lines.push(`  (${h.similarity.toFixed(2)}, ${h.type === 'long_term' ? 'long' : 'short'}-term) ${h.strategy}`);
      service.recordPatternUsage(h.patternId, true);
    }
    process.stdout.write(lines.join('\n') + '\n');
  } finally {
    service.close();
  }
}

async function consolidate(input) {
  const service = await open(input.session_id || input.sessionId || null);
  if (!service) return;
  try {
    const pruned = await service.consolidate();
    const session = await service.exportSession();
    writeFileSync(METRICS_PATH, JSON.stringify({
      updatedAt: new Date().toISOString(),
      provider: service._getState('embedding_provider'),
      consolidation: pruned,
      session,
      stats: service.getStats(),
    }, null, 2));
  } finally {
    service.close();
  }
}

async function stats(input) {
  const service = await open(input.session_id || null);
  if (!service) return;
  try { process.stdout.write(JSON.stringify(service.getStats(), null, 2) + '\n'); }
  finally { service.close(); }
}

// ── entry ────────────────────────────────────────────────────────────────────

const COMMANDS = { recall, capture, consolidate, stats };

async function main() {
  const command = process.argv[2];
  const run = COMMANDS[command];
  if (!run) {
    process.stderr.write(`Usage: learning-hook.mjs <${Object.keys(COMMANDS).join('|')}>\n`);
    return;
  }
  let input = {};
  try { input = JSON.parse((await readStdin()).trim() || '{}'); } catch { /* no payload */ }
  await run(input);
}

// A learning hook must never be the reason a turn fails.
main().catch((e) => {
  process.stderr.write(`[learning] ${e.message}\n`);
}).finally(() => process.exit(0));
