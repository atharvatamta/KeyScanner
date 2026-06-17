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
import { scanContent } from './scanner.js';
import { patterns } from './patterns.js';

const USER_AGENT = 'keyscanner/1.0 (security research)';
const jsBeautify = beautify.js;

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

export default scanGitHub;
