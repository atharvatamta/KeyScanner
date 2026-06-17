/**
 * Core scanning logic.
 *
 * scanUrl(targetUrl, options) fetches a page, pulls out its JavaScript
 * (linked + inline), beautifies it, and runs every secret pattern against
 * the result.
 */

import fetch from 'node-fetch';
import * as cheerio from 'cheerio';
import beautify from 'js-beautify';
import pLimit from 'p-limit';
import { patterns } from './patterns.js';

const USER_AGENT =
  'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 ' +
  '(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36 keyscanner/1.0';

// Linked scripts we don't bother scanning — well-known vendored libraries
// and trackers that won't contain a site's own secrets.
const CDN_SKIP = [
  'jquery',
  'bootstrap',
  'google-analytics',
  'googletagmanager',
  'gtm.js',
  'gtag',
  'analytics',
  'fbevents',
  'connect.facebook',
  'polyfill',
];

const jsBeautify = beautify.js;

/**
 * Fetch a URL with a timeout and a realistic User-Agent.
 * Returns the response text, or throws.
 */
async function fetchText(url, { timeout = 10000, verbose = false } = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, {
      headers: { 'User-Agent': USER_AGENT, Accept: '*/*' },
      signal: controller.signal,
      redirect: 'follow',
    });
    if (!res.ok) {
      throw new Error(`HTTP ${res.status} ${res.statusText}`);
    }
    return await res.text();
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Should this script src be skipped (known CDN / tracker)?
 */
function isSkippableCdn(url) {
  const lower = url.toLowerCase();
  return CDN_SKIP.some((needle) => lower.includes(needle));
}

/**
 * Resolve a possibly-relative or protocol-relative URL against a base.
 */
function resolveUrl(src, base) {
  try {
    if (src.startsWith('//')) {
      const baseProto = new URL(base).protocol;
      return `${baseProto}${src}`;
    }
    return new URL(src, base).toString();
  } catch {
    return null;
  }
}

/**
 * Run every pattern against a single piece of content.
 *
 * @param {string} content   The (ideally beautified) source to scan.
 * @param {string} fileLabel Where this content came from (url / "inline #n").
 * @returns {Array<{type,severity,match,file,lineNumber}>}
 */
export function scanContent(content, fileLabel) {
  const findings = [];
  if (!content) return findings;

  for (const { name, regex, severity } of patterns) {
    // Reset lastIndex so a shared /g regex doesn't carry state between files.
    regex.lastIndex = 0;
    let m;
    while ((m = regex.exec(content)) !== null) {
      const matchText = m[0];
      // Guard against zero-width matches causing an infinite loop.
      if (m.index === regex.lastIndex) regex.lastIndex++;

      const lineNumber = content.slice(0, m.index).split('\n').length;
      findings.push({
        type: name,
        severity,
        match: matchText,
        file: fileLabel,
        lineNumber,
      });
    }
  }
  return findings;
}

/**
 * Beautify then scan. Beautify can fail on pathological input, so it's
 * wrapped — we fall back to the raw content rather than dropping a file.
 */
function beautifyAndScan(content, fileLabel) {
  let expanded = content;
  try {
    expanded = jsBeautify(content, { indent_size: 2 });
  } catch {
    expanded = content;
  }
  return scanContent(expanded, fileLabel);
}

/**
 * Deduplicate findings by (type + match) so the same leaked key surfaced
 * across multiple files is only reported once.
 */
function dedupe(findings) {
  const seen = new Set();
  const out = [];
  for (const f of findings) {
    const key = `${f.type}::${f.match}`;
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(f);
  }
  return out;
}

/**
 * Scan a single page for exposed secrets in its JavaScript.
 *
 * @param {string} targetUrl
 * @param {object} options
 * @param {number} [options.concurrency=3]
 * @param {number} [options.timeout=10000]
 * @param {boolean} [options.includeInline=true]
 * @param {boolean} [options.verbose=false]
 * @returns {Promise<{url, scannedFiles, findings}>}
 */
export async function scanUrl(targetUrl, options = {}) {
  const {
    concurrency = 3,
    timeout = 10000,
    includeInline = true,
    verbose = false,
  } = options;

  let html;
  try {
    html = await fetchText(targetUrl, { timeout, verbose });
  } catch (err) {
    throw new Error(`Could not reach ${targetUrl}: ${err.message}`);
  }

  const $ = cheerio.load(html);

  // Collect linked script URLs.
  const scriptUrls = [];
  $('script[src]').each((_, el) => {
    const src = $(el).attr('src');
    if (!src) return;
    const resolved = resolveUrl(src, targetUrl);
    if (!resolved) return;
    if (isSkippableCdn(resolved)) {
      if (verbose) console.warn(`  ↪ skipping CDN/tracker: ${resolved}`);
      return;
    }
    scriptUrls.push(resolved);
  });

  // Collect inline scripts.
  const inlineBlocks = [];
  if (includeInline) {
    $('script:not([src])').each((i, el) => {
      const code = $(el).html();
      if (code && code.trim().length > 0) {
        inlineBlocks.push({ label: `${targetUrl} (inline #${i + 1})`, code });
      }
    });
  }

  const allFindings = [];
  let scannedFiles = 0;

  // Scan inline blocks (already in-memory, no fetch needed).
  for (const block of inlineBlocks) {
    if (verbose) console.error(`  • scanning ${block.label}`);
    allFindings.push(...beautifyAndScan(block.code, block.label));
    scannedFiles++;
  }

  // Fetch + scan linked scripts with bounded concurrency.
  const limit = pLimit(concurrency);
  await Promise.all(
    scriptUrls.map((url) =>
      limit(async () => {
        try {
          if (verbose) console.error(`  • fetching ${url}`);
          const code = await fetchText(url, { timeout, verbose });
          allFindings.push(...beautifyAndScan(code, url));
          scannedFiles++;
        } catch (err) {
          if (verbose) console.warn(`  ⚠ skipped ${url}: ${err.message}`);
        }
      })
    )
  );

  return {
    url: targetUrl,
    scannedFiles,
    findings: dedupe(allFindings),
  };
}

export default scanUrl;
