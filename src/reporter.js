/**
 * Output formatting: terminal printing + JSON/CSV report files.
 */

import { writeFile } from 'node:fs/promises';
import chalk from 'chalk';

const SEVERITY_ORDER = ['critical', 'high', 'medium'];

function severityLabel(severity) {
  switch (severity) {
    case 'critical':
      return chalk.bold.red(' CRITICAL ');
    case 'high':
      return chalk.yellow(' HIGH ');
    case 'medium':
      return chalk.blue(' MEDIUM ');
    default:
      return chalk.gray(` ${severity?.toUpperCase() ?? '?'} `);
  }
}

function truncate(str, max = 60) {
  if (str == null) return '';
  return str.length > max ? `${str.slice(0, max)}…` : str;
}

/** Shorten a long URL for display while keeping it recognizable. */
function shortenUrl(url, max = 70) {
  if (!url || url.length <= max) return url;
  const head = url.slice(0, max - 20);
  const tail = url.slice(-17);
  return `${head}…${tail}`;
}

function groupBySeverity(findings) {
  const groups = { critical: [], high: [], medium: [] };
  for (const f of findings) {
    (groups[f.severity] ??= []).push(f);
  }
  return groups;
}

/**
 * Print a single page-scan result to the terminal.
 */
export function printFindings(result) {
  console.log();
  console.log(chalk.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log(chalk.bold(`Scan results for: ${result.url}`));
  console.log(chalk.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));

  const { findings } = result;

  if (!findings || findings.length === 0) {
    console.log(chalk.green('\n✓ No exposed secrets detected.\n'));
    console.log(
      chalk.gray(
        `Scanned ${result.scannedFiles} file(s). (Absence of findings is not a ` +
          `guarantee — patterns are heuristic.)\n`
      )
    );
    return;
  }

  const groups = groupBySeverity(findings);

  for (const severity of SEVERITY_ORDER) {
    const group = groups[severity];
    if (!group || group.length === 0) continue;
    console.log();
    for (const f of group) {
      console.log(`${severityLabel(severity)} ${chalk.bold(f.type)}`);
      console.log(`   value: ${chalk.dim(truncate(f.match, 60))}`);
      console.log(
        `   at:    ${chalk.cyan(shortenUrl(f.file))}:${chalk.magenta(f.lineNumber)}`
      );
    }
  }

  const criticalCount = groups.critical?.length ?? 0;
  const highCount = groups.high?.length ?? 0;
  const mediumCount = groups.medium?.length ?? 0;

  console.log();
  console.log(
    chalk.bold(
      `${findings.length} finding(s) across ${result.scannedFiles} file(s) ` +
        `(${chalk.red(criticalCount + ' critical')}, ` +
        `${chalk.yellow(highCount + ' high')}, ` +
        `${chalk.blue(mediumCount + ' medium')}).`
    )
  );
  console.log();
}

/**
 * Print GitHub scan results to the terminal.
 */
export function printGithubFindings(results) {
  console.log();
  console.log(chalk.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));
  console.log(chalk.bold('GitHub scan results'));
  console.log(chalk.bold('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━'));

  if (!results || results.length === 0) {
    console.log(chalk.green('\n✓ No exposed secrets detected in scanned files.\n'));
    return;
  }

  let total = 0;
  let critical = 0;

  for (const r of results) {
    console.log();
    console.log(`${chalk.bold(r.repo)} ${chalk.gray('—')} ${chalk.cyan(r.file)}`);
    console.log(`   ${chalk.dim(r.htmlUrl)}`);
    for (const f of r.findings) {
      total++;
      if (f.severity === 'critical') critical++;
      console.log(
        `   ${severityLabel(f.severity)} ${chalk.bold(f.type)} ` +
          `${chalk.dim('→ ' + truncate(f.match, 50))} (line ${f.lineNumber})`
      );
    }
  }

  console.log();
  console.log(
    chalk.bold(
      `${total} finding(s) across ${results.length} file(s) ` +
        `(${chalk.red(critical + ' critical')}).`
    )
  );
  console.log();
}

export function buildJsonReport(result) {
  const groups = groupBySeverity(result.findings || []);
  return {
    timestamp: new Date().toISOString(),
    scannedUrl: result.url,
    scannedFiles: result.scannedFiles,
    totalFindings: result.findings?.length ?? 0,
    findingsBySeverity: {
      critical: groups.critical?.length ?? 0,
      high: groups.high?.length ?? 0,
      medium: groups.medium?.length ?? 0,
    },
    allFindings: result.findings ?? [],
  };
}

/**
 * Save a full JSON report to disk.
 */
export async function saveReport(result, outputPath) {
  const report = buildJsonReport(result);
  await writeFile(outputPath, JSON.stringify(report, null, 2), 'utf8');
  // Status messages go to stderr so they never corrupt piped stdout JSON.
  console.error(chalk.gray(`📄 JSON report written to ${outputPath}`));
}

function csvEscape(value) {
  const s = String(value ?? '');
  if (/[",\n]/.test(s)) {
    return `"${s.replace(/"/g, '""')}"`;
  }
  return s;
}

/**
 * Save a CSV report to disk.
 * Columns: url, file, type, severity, match, lineNumber
 */
export async function saveCsvReport(result, outputPath) {
  const rows = [['url', 'file', 'type', 'severity', 'match', 'lineNumber']];
  for (const f of result.findings ?? []) {
    rows.push([
      result.url,
      f.file,
      f.type,
      f.severity,
      f.match,
      f.lineNumber,
    ]);
  }
  const csv = rows.map((r) => r.map(csvEscape).join(',')).join('\n');
  await writeFile(outputPath, csv, 'utf8');
  console.error(chalk.gray(`📄 CSV report written to ${outputPath}`));
}

/**
 * Append rows from one site result into an aggregate CSV array (used by bulk).
 */
export function buildCsvRows(result) {
  const rows = [];
  for (const f of result.findings ?? []) {
    rows.push([result.url, f.file, f.type, f.severity, f.match, f.lineNumber]);
  }
  return rows;
}

export async function saveAggregateCsv(allRows, outputPath) {
  const header = ['url', 'file', 'type', 'severity', 'match', 'lineNumber'];
  const rows = [header, ...allRows];
  const csv = rows.map((r) => r.map(csvEscape).join(',')).join('\n');
  await writeFile(outputPath, csv, 'utf8');
  console.error(chalk.gray(`📄 Aggregate CSV written to ${outputPath}`));
}
