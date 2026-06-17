/**
 * GitHub public-source scanning.
 *
 * Uses the GitHub Code Search API to locate public files matching a query,
 * then scans their raw content with the same patterns as scanner.js.
 *
 * Intended use: finding *your own* leaked secrets, or secrets you intend to
 * responsibly disclose to the affected owner. Never use discovered keys.
 */

import fetch from 'node-fetch';
import beautify from 'js-beautify';
import pLimit from 'p-limit';
import { scanContent } from './scanner.js';
import { patterns } from './patterns.js';

const USER_AGENT = 'keyscanner/1.0 (security research)';
const jsBeautify = beautify.js;

// File types worth scanning in a full-repo (--self) sweep. Anything else
// (images, fonts, archives, compiled binaries) is skipped.
const SCANNABLE_EXT = new Set([
  'js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs', 'vue', 'svelte',
  'json', 'json5', 'yml', 'yaml', 'toml', 'ini', 'cfg', 'conf', 'config',
  'env', 'properties', 'xml', 'html', 'htm',
  'py', 'rb', 'go', 'php', 'java', 'cs', 'kt', 'swift', 'rs', 'c', 'cpp', 'h',
  'sh', 'bash', 'zsh', 'ps1', 'tf', 'tfvars', 'gradle', 'txt', 'md',
]);

// Extensionless filenames that commonly hold secrets/config.
const SCANNABLE_NAMES = new Set([
  '.env', 'dockerfile', 'makefile', '.npmrc', '.netrc', 'procfile',
]);

const JS_LIKE_EXT = new Set(['js', 'jsx', 'ts', 'tsx', 'mjs', 'cjs']);

function isScannablePath(p) {
  const name = p.split('/').pop().toLowerCase();
  if (SCANNABLE_NAMES.has(name)) return true;
  if (name.startsWith('.env')) return true; // .env.local, .env.production, …
  const dot = name.lastIndexOf('.');
  if (dot < 0) return false;
  return SCANNABLE_EXT.has(name.slice(dot + 1));
}

/**
 * Thrown when GitHub responds with a rate-limit error. Carries the reset
 * time so the CLI can show the user when to retry.
 */
export class RateLimitError extends Error {
  constructor(message, resetDate) {
    super(message);
    this.name = 'RateLimitError';
    this.resetDate = resetDate;
  }
}

function buildHeaders(token) {
  const headers = {
    Accept: 'application/vnd.github.v3+json',
    'User-Agent': USER_AGENT,
  };
  if (token) headers.Authorization = `Bearer ${token}`;
  return headers;
}

/**
 * Detect & translate a rate-limit response into a RateLimitError.
 */
function checkRateLimit(res) {
  const remaining = res.headers.get('x-ratelimit-remaining');
  if (res.status === 403 && remaining === '0') {
    const resetUnix = Number(res.headers.get('x-ratelimit-reset'));
    const resetDate = Number.isFinite(resetUnix)
      ? new Date(resetUnix * 1000)
      : null;
    throw new RateLimitError(
      'GitHub API rate limit exceeded.',
      resetDate
    );
  }
}

/**
 * Convert a GitHub html_url for a blob into its raw.githubusercontent.com
 * equivalent.
 *   https://github.com/owner/repo/blob/sha/path
 * → https://raw.githubusercontent.com/owner/repo/sha/path
 */
function toRawUrl(item) {
  try {
    const repoFull = item.repository?.full_name;
    const sha = item.sha;
    const path = item.path;
    // Prefer the documented git_url-free construction using the default ref
    // from html_url, which reliably contains the blob ref.
    const html = item.html_url || '';
    const m = html.match(/github\.com\/[^/]+\/[^/]+\/blob\/([^/]+)\/(.*)$/);
    if (repoFull && m) {
      return `https://raw.githubusercontent.com/${repoFull}/${m[1]}/${m[2]}`;
    }
    if (repoFull && sha && path) {
      return `https://raw.githubusercontent.com/${repoFull}/${sha}/${path}`;
    }
  } catch {
    /* fall through */
  }
  return null;
}

async function fetchRaw(url, token, timeout = 10000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, {
      headers: buildHeaders(token),
      signal: controller.signal,
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}`);
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Scan public GitHub code for a query.
 *
 * @param {string} query   Code search query (e.g. "AIzaSy firebase").
 * @param {object} options
 * @param {string} [options.token]       GitHub PAT (recommended).
 * @param {number} [options.maxResults=10]
 * @param {boolean} [options.verbose=false]
 * @returns {Promise<Array<{repo, file, htmlUrl, findings}>>}
 */
export async function scanGitHub(query, options = {}) {
  const { token, maxResults = 10, verbose = false } = options;

  const searchUrl =
    'https://api.github.com/search/code?q=' +
    encodeURIComponent(`${query} language:javascript`) +
    `&per_page=${Math.min(Math.max(maxResults, 1), 100)}`;

  let searchRes;
  try {
    searchRes = await fetch(searchUrl, { headers: buildHeaders(token) });
  } catch (err) {
    throw new Error(`GitHub search request failed: ${err.message}`);
  }

  checkRateLimit(searchRes);

  if (searchRes.status === 401) {
    throw new Error('GitHub authentication failed — check your --token.');
  }
  if (!searchRes.ok) {
    const body = await searchRes.text().catch(() => '');
    throw new Error(
      `GitHub search failed: HTTP ${searchRes.status} ${body.slice(0, 200)}`
    );
  }

  const data = await searchRes.json();
  const items = (data.items || []).slice(0, maxResults);

  if (verbose) {
    console.error(`  Found ${data.total_count ?? items.length} total matches; ` +
      `scanning up to ${items.length}.`);
  }

  const results = [];
  for (const item of items) {
    const rawUrl = toRawUrl(item);
    const repo = item.repository?.full_name ?? 'unknown';
    const file = item.path ?? 'unknown';
    const htmlUrl = item.html_url ?? '';

    if (!rawUrl) {
      if (verbose) console.warn(`  ⚠ could not resolve raw url for ${repo}/${file}`);
      continue;
    }

    try {
      if (verbose) console.error(`  • scanning ${repo}/${file}`);
      const content = await fetchRaw(rawUrl, token);
      let expanded = content;
      try {
        expanded = jsBeautify(content, { indent_size: 2 });
      } catch {
        expanded = content;
      }
      const findings = scanContent(expanded, `${repo}/${file}`);
      if (findings.length > 0) {
        results.push({ repo, file, htmlUrl, findings });
      }
    } catch (err) {
      if (verbose) console.warn(`  ⚠ skipped ${repo}/${file}: ${err.message}`);
    }
  }

  return results;
}

/**
 * Scan GitHub using *every* built-in pattern that has a search seed, instead
 * of a single user-supplied query. For each seed it runs a code search, then
 * (via scanGitHub) fetches the matched files and applies the FULL pattern set
 * to each — the same detection a website scan does. Results from different
 * seeds that point at the same file are merged and de-duplicated.
 *
 * @param {object} options
 * @param {string} [options.token]
 * @param {number} [options.maxResults=10]  Max files per seed.
 * @param {boolean} [options.verbose=false]
 * @returns {Promise<Array<{repo, file, htmlUrl, findings}>>}
 */
export async function scanGitHubAll(options = {}) {
  const { token, maxResults = 10, verbose = false } = options;

  // Unique search seeds drawn from the pattern list.
  const seeds = [];
  const seenSeed = new Set();
  for (const p of patterns) {
    if (p.search && !seenSeed.has(p.search)) {
      seenSeed.add(p.search);
      seeds.push({ name: p.name, q: p.search });
    }
  }

  if (verbose) {
    console.error(`  --all: running ${seeds.length} pattern-based searches.`);
  }

  // Merge findings per file across all seed searches.
  const merged = new Map(); // "repo::file" -> { repo, file, htmlUrl, findings }

  for (const seed of seeds) {
    if (verbose) {
      console.error(`\n  ── ${seed.name}: searching "${seed.q}" ──`);
    }
    let results;
    try {
      results = await scanGitHub(seed.q, { token, maxResults, verbose });
    } catch (err) {
      if (err instanceof RateLimitError) {
        console.error(
          `  ⚠ rate limit hit while searching "${seed.q}" — stopping early ` +
            `with partial results.`
        );
        if (err.resetDate) {
          console.error(`    resets at ${err.resetDate.toLocaleString()}`);
        }
        break;
      }
      console.error(`  ⚠ search "${seed.q}" failed: ${err.message}`);
      continue;
    }

    for (const r of results) {
      const key = `${r.repo}::${r.file}`;
      if (!merged.has(key)) {
        merged.set(key, {
          repo: r.repo,
          file: r.file,
          htmlUrl: r.htmlUrl,
          findings: [],
        });
      }
      merged.get(key).findings.push(...r.findings);
    }
  }

  // De-duplicate findings within each file by (type + match).
  const out = [];
  for (const entry of merged.values()) {
    const seenF = new Set();
    entry.findings = entry.findings.filter((f) => {
      const k = `${f.type}::${f.match}`;
      if (seenF.has(k)) return false;
      seenF.add(k);
      return true;
    });
    out.push(entry);
  }
  return out;
}

/**
 * Authenticated GET returning parsed JSON, with rate-limit / error handling.
 */
async function ghJson(url, token, timeout = 15000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  let res;
  try {
    res = await fetch(url, { headers: buildHeaders(token), signal: controller.signal });
  } catch (err) {
    throw new Error(`request to ${url} failed: ${err.message}`);
  } finally {
    clearTimeout(timer);
  }
  checkRateLimit(res);
  if (res.status === 401) {
    throw new Error('GitHub authentication failed — check your --token.');
  }
  if (!res.ok) {
    const body = await res.text().catch(() => '');
    throw new Error(`GitHub API ${res.status} for ${url}: ${body.slice(0, 160)}`);
  }
  return res.json();
}

/**
 * Scan every scannable file in a single repo (default branch) by reading the
 * recursive git tree and fetching each blob. Works for private repos too,
 * since blobs are fetched with the authenticated API (not the raw host).
 *
 * @returns {Promise<Array<{repo, file, htmlUrl, findings}>>} one entry per
 *          file that had at least one finding.
 */
async function scanRepo(repo, token, opts = {}) {
  const {
    maxFiles = 400,
    maxBytes = 1_000_000,
    concurrency = 6,
    verbose = false,
  } = opts;

  const branch = repo.default_branch;
  if (!branch) return [];

  let tree;
  try {
    tree = await ghJson(
      `https://api.github.com/repos/${repo.full_name}/git/trees/${branch}?recursive=1`,
      token
    );
  } catch (err) {
    if (err instanceof RateLimitError) throw err;
    if (verbose) console.error(`  ⚠ ${repo.full_name}: could not read tree: ${err.message}`);
    return [];
  }

  let blobs = (tree.tree || []).filter(
    (t) => t.type === 'blob' && isScannablePath(t.path) && (t.size == null || t.size <= maxBytes)
  );

  if (tree.truncated && verbose) {
    console.error(`  ⚠ ${repo.full_name}: git tree was truncated by GitHub — some files skipped.`);
  }
  if (blobs.length > maxFiles) {
    if (verbose) {
      console.error(`  ⚠ ${repo.full_name}: ${blobs.length} files, scanning first ${maxFiles}.`);
    }
    blobs = blobs.slice(0, maxFiles);
  }

  if (verbose) {
    console.error(`  • ${repo.full_name} (${repo.private ? 'private' : 'public'}): ${blobs.length} files`);
  }

  const limit = pLimit(concurrency);
  const perFile = [];

  await Promise.all(
    blobs.map((b) =>
      limit(async () => {
        try {
          const blob = await ghJson(
            `https://api.github.com/repos/${repo.full_name}/git/blobs/${b.sha}`,
            token
          );
          let content =
            blob.encoding === 'base64'
              ? Buffer.from(blob.content || '', 'base64').toString('utf8')
              : blob.content || '';

          const ext = b.path.split('.').pop().toLowerCase();
          if (JS_LIKE_EXT.has(ext)) {
            try {
              content = jsBeautify(content, { indent_size: 2 });
            } catch {
              /* keep raw */
            }
          }

          const findings = scanContent(content, `${repo.full_name}/${b.path}`);
          if (findings.length > 0) {
            perFile.push({
              repo: repo.full_name,
              file: b.path,
              htmlUrl: `${repo.html_url}/blob/${branch}/${b.path}`,
              findings,
            });
          }
        } catch (err) {
          if (err instanceof RateLimitError) throw err;
          if (verbose) console.error(`  ⚠ ${repo.full_name}/${b.path}: ${err.message}`);
        }
      })
    )
  );

  return perFile;
}

/**
 * Scan all repos owned by the authenticated user for exposed secrets.
 * This is a defensive self-audit: it reads YOUR OWN repos (public + private)
 * via your token and reports what's leaking so you can rotate/remove it.
 *
 * @param {object} options
 * @param {string} options.token            Required — identifies "self".
 * @param {number} [options.maxRepos=20]    Max repos to scan (most-recently updated first).
 * @param {boolean} [options.includeForks=false]
 * @param {number} [options.concurrency=4]  Repos scanned in parallel.
 * @param {boolean} [options.verbose=false]
 * @returns {Promise<Array<{repo, file, htmlUrl, findings}>>}
 */
export async function scanGitHubSelf(options = {}) {
  const {
    token,
    maxRepos = 20,
    includeForks = false,
    concurrency = 4,
    verbose = false,
  } = options;

  if (!token) {
    throw new Error("--self requires a --token: it scans YOUR authenticated account's repos.");
  }

  const me = await ghJson('https://api.github.com/user', token);
  if (verbose) console.error(`  authenticated as ${me.login}`);

  // List owned repos (paginated), most-recently-updated first.
  const repos = [];
  for (let page = 1; page <= 10; page++) {
    const batch = await ghJson(
      `https://api.github.com/user/repos?per_page=100&page=${page}&affiliation=owner&sort=updated`,
      token
    );
    if (!Array.isArray(batch) || batch.length === 0) break;
    for (const r of batch) {
      if (!includeForks && r.fork) continue;
      repos.push(r);
    }
    if (batch.length < 100 || repos.length >= maxRepos) break;
  }

  const target = repos.slice(0, maxRepos);
  if (verbose) {
    console.error(`  scanning ${target.length} repo(s) of ${me.login} (max ${maxRepos}).`);
  }
  if (repos.length > maxRepos) {
    console.error(
      `  note: you own more than ${maxRepos} repos; scanning the ${maxRepos} most ` +
        `recently updated. Raise with --max.`
    );
  }

  const repoLimit = pLimit(concurrency);
  const all = [];

  try {
    const results = await Promise.all(
      target.map((repo) =>
        repoLimit(() =>
          scanRepo(repo, token, { verbose }).catch((err) => {
            if (err instanceof RateLimitError) throw err;
            if (verbose) console.error(`  ⚠ ${repo.full_name}: ${err.message}`);
            return [];
          })
        )
      )
    );
    for (const r of results) all.push(...r);
  } catch (err) {
    if (err instanceof RateLimitError) {
      console.error('  ⚠ rate limit hit — returning partial results.');
      if (err.resetDate) console.error(`    resets at ${err.resetDate.toLocaleString()}`);
    } else {
      throw err;
    }
  }

  return all;
}

export default scanGitHub;
