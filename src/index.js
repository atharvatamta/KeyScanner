#!/usr/bin/env node
/**
 * keyscanner — CLI entry point.
 *
 * A security-research tool that scans website frontend JavaScript (and public
 * GitHub source) for accidentally exposed API keys, so they can be reported
 * and remediated. Detect-and-report only — it never uses discovered keys.
 */

import { readFile, mkdir } from 'node:fs/promises';
import path from 'node:path';
import readline from 'node:readline/promises';
import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import pLimit from 'p-limit';

import { scanUrl } from './scanner.js';
import { scanGitHub, scanGitHubAll, scanGitHubSelf, RateLimitError } from './github.js';
import { BANNER, BANNER_WIDTH } from './banner.js';
import {
  printFindings,
  printGithubFindings,
  saveReport,
  saveCsvReport,
  buildCsvRows,
  saveAggregateCsv,
  buildJsonReport,
} from './reporter.js';

const program = new Command();

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

/**
 * Print the startup banner to stderr (so it never corrupts --json stdout).
 * On terminals narrower than the block art, fall back to a compact one-liner
 * — unless `force` is set (explicit `banner` command), which always shows
 * the full art.
 *
 * In an interactive terminal the art is revealed line-by-line, top to bottom.
 * When stderr isn't a TTY (piped/redirected) — or KEYSCANNER_NO_ANIM is set —
 * it prints instantly so scripts and CI stay fast.
 */
async function printBanner(force = false) {
  const cols = process.stderr.columns || 80;
  if (force || cols >= BANNER_WIDTH) {
    const animate = process.stderr.isTTY && !process.env.KEYSCANNER_NO_ANIM;
    if (animate) {
      for (const line of BANNER.split('\n')) {
        console.error(chalk.cyan(line));
        await sleep(50);
      }
    } else {
      console.error(chalk.cyan(BANNER));
    }
  } else {
    console.error(chalk.bold.cyan('keyscanner'));
  }
  console.error(
    chalk.dim(' detect & report, never exploit \n by Atharva Tamta') + '\n'
  );
}

/**
 * Interactive startup menu shown when keyscanner is run with no arguments in
 * a terminal. Walks the user through the two main scan modes and returns the
 * argv to dispatch (e.g. ['scan', 'https://…']), the string 'help' to print
 * full usage, or null to quit. Prompts go to stderr so stdout stays clean.
 */
async function interactiveMenu() {
  // terminal:false keeps stdin in the OS console's cooked/line mode, so pasting
  // a URL or token works natively on Windows. (In readline's default raw mode,
  // a pasted burst of characters is often dropped — only typed keys arrive.)
  const rl = readline.createInterface({
    input: process.stdin,
    output: process.stderr,
    terminal: false,
  });
  const num = (n) => chalk.cyan.bold(n);
  // Strip bracketed-paste markers / control chars some terminals wrap around
  // pasted text, then trim surrounding whitespace.
  const clean = (s) =>
    s.replace(/\x1b\[20[01]~/g, '').replace(/[\x00-\x1f\x7f]/g, '').trim();
  const ask = async (prompt) => clean(await rl.question(prompt));
  try {
    console.error(chalk.bold('What would you like to scan?\n'));
    console.error(`  ${num('1')}  A website   ${chalk.gray('— fetch a URL and scan its JavaScript for exposed keys')}`);
    console.error(`  ${num('2')}  GitHub      ${chalk.gray('— search public code, or audit your own repos')}`);
    console.error(`  ${num('3')}  All commands & options`);
    console.error(`  ${num('q')}  Quit\n`);

    const choice = (await ask(chalk.bold('Choose [1/2/3/q]: '))).toLowerCase();

    if (choice === '1') {
      const url = await ask('\nWebsite URL: ');
      if (!url) {
        console.error(chalk.red('No URL entered — nothing to scan.'));
        return null;
      }
      return ['scan', url];
    }

    if (choice === '2') {
      console.error(`\n  ${num('1')}  Search by keyword/query   ${chalk.gray('e.g. "AIzaSy firebase"')}`);
      console.error(`  ${num('2')}  Scan with all built-in patterns`);
      console.error(`  ${num('3')}  Audit my own repos        ${chalk.gray('(--self, needs a token)')}\n`);
      const sub = await ask(chalk.bold('Choose [1/2/3]: '));

      // A token greatly raises GitHub's rate limit and is required for --self.
      const tokenInput = await ask(
        chalk.gray('GitHub token (Enter to use $GITHUB_TOKEN or skip): ')
      );
      const tokenArgs = tokenInput ? ['--token', tokenInput] : [];

      if (sub === '1') {
        const query = await ask('\nSearch query: ');
        if (!query) {
          console.error(chalk.red('No query entered.'));
          return null;
        }
        return ['github', query, ...tokenArgs];
      }
      if (sub === '2') return ['github', '--all', ...tokenArgs];
      if (sub === '3') {
        if (!tokenInput && !process.env.GITHUB_TOKEN) {
          console.error(chalk.red('Self-audit needs a token. Pass one here or set $GITHUB_TOKEN.'));
          return null;
        }
        return ['github', '--self', ...tokenArgs];
      }
      console.error(chalk.red('Unrecognized choice.'));
      return null;
    }

    if (choice === '3' || choice === 'h' || choice === 'help') return 'help';

    // 'q', empty, or anything else: quit quietly.
    return null;
  } finally {
    rl.close();
  }
}

program
  .name('keyscanner')
  .description(
    'Scan website frontend JavaScript and public source for exposed API keys.\n' +
      'Responsible-disclosure tool: always report findings, never exploit them.'
  )
  .version('1.0.0')
  .option('--no-banner', 'Suppress the startup banner');

// Show the banner before any command action, but skip it for --json output
// (kept clean) and when --no-banner is set. --help / --version never trigger
// preAction, so they stay banner-free automatically.
program.hook('preAction', async (thisCommand, actionCommand) => {
  // The `banner` command prints the banner itself — don't double it here.
  if (actionCommand.name() === 'banner') return;
  const opts = actionCommand.opts();
  if (program.opts().banner !== false && !opts.json) {
    await printBanner();
  }
});

/* ---------------------------------------------------------------- banner -- */
program
  .command('banner')
  .description('Print the keyscanner banner and exit')
  .action(async () => {
    await printBanner(true);
  });

/* ------------------------------------------------------------------ scan -- */
program
  .command('scan')
  .description('Scan a single URL for exposed API keys in its JavaScript')
  .argument('<url>', 'Target URL to scan')
  .option('-o, --output <file>', 'Save JSON report to file')
  .option('--csv <file>', 'Save CSV report to file')
  .option('-c, --concurrency <n>', 'Parallel JS file fetches', '3')
  .option('-t, --timeout <ms>', 'Request timeout in ms', '10000')
  .option('--no-inline', 'Skip inline <script> blocks')
  .option('--json', 'Print the JSON report to stdout (suppresses formatted output)', false)
  .option('-v, --verbose', 'Show each file being scanned', false)
  .action(async (url, opts) => {
    // In JSON mode, keep stdout clean: spinner/verbose logs go to stderr.
    const jsonMode = opts.json;
    const spinner = jsonMode ? null : ora('Scanning JS files...').start();
    let result;
    try {
      result = await scanUrl(url, {
        concurrency: parseInt(opts.concurrency, 10) || 3,
        timeout: parseInt(opts.timeout, 10) || 10000,
        includeInline: opts.inline !== false,
        verbose: opts.verbose,
      });
      spinner?.succeed(`Scanned ${result.scannedFiles} file(s).`);
    } catch (err) {
      spinner?.fail('Scan failed.');
      console.error(chalk.red(`Error: ${err.message}`));
      process.exit(2);
    }

    if (jsonMode) {
      process.stdout.write(JSON.stringify(buildJsonReport(result), null, 2) + '\n');
    } else {
      printFindings(result);
    }

    try {
      if (opts.output) await saveReport(result, opts.output);
      if (opts.csv) await saveCsvReport(result, opts.csv);
    } catch (err) {
      console.error(chalk.red(`Failed to write report: ${err.message}`));
    }

    const criticalCount = result.findings.filter(
      (f) => f.severity === 'critical'
    ).length;
    process.exit(criticalCount > 0 ? 1 : 0);
  });

/* ---------------------------------------------------------------- github -- */
program
  .command('github')
  .description('Scan GitHub for exposed API keys (code search, --all patterns, or --self repo audit)')
  .argument('[query]', 'Code search query (omit when using --all or --self)')
  .option('--token <token>', 'GitHub personal access token (recommended)')
  .option('--all', 'Scan using ALL built-in patterns instead of one query', false)
  .option('--self', "Audit ALL repos owned by your authenticated account (public + private)", false)
  .option('--max <n>', 'Max files per pattern (--all), or max repos (--self)', '10')
  .option('-o, --output <file>', 'Save JSON report')
  .option('--json', 'Print the JSON report to stdout (suppresses formatted output)', false)
  .option('-v, --verbose', 'Show each file being scanned', false)
  .addHelpText(
    'after',
    `
Example queries:
  $ keyscanner github "AIzaSy firebase"
  $ keyscanner github "sk_live_ stripe payment"
  $ keyscanner github "AKIA amazonaws"

Scan with every built-in pattern (no query needed):
  $ keyscanner github --all --token "$GITHUB_TOKEN"
  $ keyscanner github --all --max 5 --json

Audit your own account's repos (self-audit, public + private):
  $ keyscanner github --self --token "$GITHUB_TOKEN"
  $ keyscanner github --self --max 50 -o my-audit.json

Note: GitHub Code Search requires authentication for most queries.
--self requires a token. Pass --token, or set GITHUB_TOKEN.`
  )
  .action(async (query, opts) => {
    const token = opts.token || process.env.GITHUB_TOKEN;
    const jsonMode = opts.json;

    if (opts.self && !token) {
      console.error(
        chalk.red('Error: --self requires a --token (it scans your account\'s repos).')
      );
      process.exit(2);
    }
    if (!opts.self && !opts.all && !query) {
      console.error(
        chalk.red('Error: provide a search query, or use --all (every pattern) ' +
          'or --self (your own repos).')
      );
      process.exit(2);
    }
    if (query && (opts.all || opts.self)) {
      console.error(
        chalk.yellow(`Note: ${opts.self ? '--self' : '--all'} ignores the provided query.`)
      );
    }

    const mode = opts.self ? 'self' : opts.all ? 'all-patterns' : 'query';
    const spinnerText = {
      self: 'Auditing your GitHub repos...',
      'all-patterns': 'Searching GitHub (all patterns)...',
      query: 'Searching GitHub...',
    }[mode];
    const spinner = jsonMode ? null : ora(spinnerText).start();

    let results;
    try {
      const maxN = parseInt(opts.max, 10) || (opts.self ? 20 : 10);
      if (opts.self) {
        results = await scanGitHubSelf({ token, maxRepos: maxN, verbose: opts.verbose });
      } else if (opts.all) {
        results = await scanGitHubAll({ token, maxResults: maxN, verbose: opts.verbose });
      } else {
        results = await scanGitHub(query, { token, maxResults: maxN, verbose: opts.verbose });
      }
      spinner?.succeed(opts.self ? 'Self-audit complete.' : 'GitHub scan complete.');
    } catch (err) {
      spinner?.fail('GitHub scan failed.');
      if (err instanceof RateLimitError) {
        console.error(chalk.red(err.message));
        if (err.resetDate) {
          console.error(
            chalk.yellow(`Rate limit resets at: ${err.resetDate.toLocaleString()}`)
          );
        }
        console.error(
          chalk.gray('Tip: authenticate with --token for a much higher limit.')
        );
      } else {
        console.error(chalk.red(`Error: ${err.message}`));
      }
      process.exit(2);
    }

    const queryLabel = {
      self: '(self: all owned repos)',
      'all-patterns': '(all built-in patterns)',
      query,
    }[mode];
    const report = {
      timestamp: new Date().toISOString(),
      query: queryLabel,
      mode,
      scannedFiles: results.length,
      totalFindings: results.reduce((n, r) => n + r.findings.length, 0),
      results,
    };

    if (jsonMode) {
      process.stdout.write(JSON.stringify(report, null, 2) + '\n');
    } else {
      printGithubFindings(results);
    }

    if (opts.output) {
      try {
        const { writeFile } = await import('node:fs/promises');
        await writeFile(opts.output, JSON.stringify(report, null, 2), 'utf8');
        console.error(chalk.gray(`📄 JSON report written to ${opts.output}`));
      } catch (err) {
        console.error(chalk.red(`Failed to write report: ${err.message}`));
      }
    }

    const hasCritical = results.some((r) =>
      r.findings.some((f) => f.severity === 'critical')
    );
    process.exit(hasCritical ? 1 : 0);
  });

/* ------------------------------------------------------------------ bulk -- */
program
  .command('bulk')
  .description('Scan many sites listed in a text file (one URL per line)')
  .argument('<file>', 'Text file with one URL per line')
  .option('-o, --output <dir>', 'Directory to save per-site JSON reports')
  .option('--csv <file>', 'Aggregate CSV of all findings')
  .option('-c, --concurrency <n>', 'Sites scanned in parallel', '2')
  .option('-t, --timeout <ms>', 'Per-request timeout in ms', '10000')
  .option('-v, --verbose', 'Show each file being scanned', false)
  .action(async (file, opts) => {
    let urls;
    try {
      const text = await readFile(file, 'utf8');
      urls = text
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l && !l.startsWith('#'));
    } catch (err) {
      console.error(chalk.red(`Could not read URL list: ${err.message}`));
      process.exit(2);
    }

    if (urls.length === 0) {
      console.error(chalk.red('No URLs found in the input file.'));
      process.exit(2);
    }

    if (opts.output) {
      await mkdir(opts.output, { recursive: true }).catch(() => {});
    }

    const concurrency = parseInt(opts.concurrency, 10) || 2;
    const limit = pLimit(concurrency);
    const total = urls.length;
    let done = 0;

    const spinner = ora(`Scanning site 0/${total}...`).start();

    const summaries = [];
    const aggregateRows = [];

    await Promise.all(
      urls.map((url) =>
        limit(async () => {
          let result;
          try {
            result = await scanUrl(url, {
              concurrency: 3,
              timeout: parseInt(opts.timeout, 10) || 10000,
              includeInline: true,
              verbose: opts.verbose,
            });
          } catch (err) {
            result = { url, scannedFiles: 0, findings: [], error: err.message };
          }
          done++;
          spinner.text = `Scanning site ${done}/${total}...`;

          const bySeverity = { critical: 0, high: 0, medium: 0 };
          for (const f of result.findings) bySeverity[f.severity]++;
          summaries.push({
            url,
            findings: result.findings.length,
            ...bySeverity,
            error: result.error,
          });

          if (opts.csv) aggregateRows.push(...buildCsvRows(result));

          if (opts.output && !result.error) {
            const safeName =
              url.replace(/[^a-z0-9]+/gi, '_').slice(0, 80) + '.json';
            try {
              await saveReport(result, path.join(opts.output, safeName));
            } catch {
              /* non-fatal */
            }
          }
        })
      )
    );

    spinner.succeed(`Scanned ${total} site(s).`);

    // Summary table.
    console.log();
    console.log(
      chalk.bold(
        pad('SITE', 50) +
          pad('FINDINGS', 10) +
          pad('CRIT', 6) +
          pad('HIGH', 6) +
          pad('MED', 6)
      )
    );
    console.log(chalk.gray('─'.repeat(78)));
    let totalCritical = 0;
    for (const s of summaries) {
      totalCritical += s.critical;
      // Pad plain text first, then apply color so widths stay aligned.
      const site = pad(truncateUrl(s.url, 48), 50);
      const line =
        (s.error ? chalk.red(site) : site) +
        pad(String(s.findings), 10) +
        chalk.red(pad(String(s.critical), 6)) +
        chalk.yellow(pad(String(s.high), 6)) +
        chalk.blue(pad(String(s.medium), 6));
      console.log(line);
      if (s.error) console.log(chalk.gray(`   ⚠ ${s.error}`));
    }
    console.log();

    if (opts.csv) {
      try {
        await saveAggregateCsv(aggregateRows, opts.csv);
      } catch (err) {
        console.error(chalk.red(`Failed to write aggregate CSV: ${err.message}`));
      }
    }

    process.exit(totalCritical > 0 ? 1 : 0);
  });

function pad(str, width) {
  const s = String(str);
  // Account for ANSI codes only roughly; used for display alignment.
  const visibleLen = s.replace(/\[[0-9;]*m/g, '').length;
  if (visibleLen >= width) return s + ' ';
  return s + ' '.repeat(width - visibleLen);
}

function truncateUrl(url, max) {
  return url.length > max ? url.slice(0, max - 1) + '…' : url;
}

// Bare `keyscanner` (no command/args): show the banner, then guide the user.
// In an interactive terminal, offer a menu (scan a website / GitHub / help).
// When piped or non-interactive, fall back to printing the full help.
if (process.argv.slice(2).length === 0) {
  await printBanner(true);
  if (process.stdin.isTTY && process.stderr.isTTY) {
    const next = await interactiveMenu();
    if (next === 'help') {
      program.outputHelp();
      process.exit(0);
    } else if (Array.isArray(next)) {
      console.error(chalk.gray(`\n› keyscanner ${next.join(' ')}\n`));
      // Banner already shown above — suppress it on the dispatched run.
      await program.parseAsync(['node', 'keyscanner', '--no-banner', ...next]);
    } else {
      process.exit(0);
    }
  } else {
    program.outputHelp();
    process.exit(0);
  }
}

program.parseAsync(process.argv).catch((err) => {
  console.error(chalk.red(`Unexpected error: ${err.message}`));
  process.exit(2);
});
