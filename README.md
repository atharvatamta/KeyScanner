# keyscanner

<img width="1024" height="761" alt="image" src="https://github.com/user-attachments/assets/55d10e57-d13c-4d4a-b696-41278fc0a909" />



`keyscanner` is a Node.js security-research CLI that scans a website's frontend JavaScript (linked and inline) — and, optionally, public GitHub source — for accidentally committed API keys and secrets. It **detects and reports** exposed credentials so they can be rotated and remediated; it never authenticates with, validates, or otherwise uses any key it finds. Think of it as a focused, browser-facing companion to tools like gitleaks or TruffleHog.

## Installation

Requires **Node.js 18+**.

```bash
git clone <this-repo> keyscanner
cd keyscanner
npm install
npm install -g .
```

After the global install, the `keyscanner` command is available on your `PATH`. You can also run it without a global install via `node src/index.js <command>`.

## Usage

### `scan` — scan a single site

```bash
keyscanner scan https://example.com
keyscanner scan https://example.com -o report.json --csv report.csv
keyscanner scan https://example.com -c 5 -t 15000 --verbose
keyscanner scan https://example.com --no-inline
```

| Option | Description | Default |
| --- | --- | --- |
| `-o, --output <file>` | Save a full JSON report | — |
| `--csv <file>` | Save a CSV report | — |
| `--json` | Print the JSON report to **stdout** (suppresses the formatted output) | off |
| `-c, --concurrency <n>` | Parallel JS file fetches | `3` |
| `-t, --timeout <ms>` | Per-request timeout | `10000` |
| `--no-inline` | Skip inline `<script>` blocks | inline on |
| `-v, --verbose` | Log each file scanned | off |

Exits with code `1` if any **critical** finding is detected (useful in CI).

#### Piping JSON

With `--json`, **only** the JSON report goes to stdout — the spinner, verbose
logs, and "report written" messages all go to stderr — so the output stays
valid JSON for piping into tools like `jq`:

```bash
keyscanner scan https://site.com --json | jq '.allFindings[] | select(.severity=="critical")'
```

The same `--json` flag is available on the `github` command.

### `github` — search public GitHub code

```bash
keyscanner github "AIzaSy firebase" --token "$GITHUB_TOKEN"
keyscanner github "sk_live_ stripe payment" --max 5
keyscanner github "AKIA amazonaws" -o gh-report.json
```

| Option | Description | Default |
| --- | --- | --- |
| `--token <token>` | GitHub personal access token (recommended; or set `GITHUB_TOKEN`) | — |
| `--all` | Scan with **every** built-in pattern instead of a single query | off |
| `--max <n>` | Max files to check (per pattern when using `--all`) | `10` |
| `-o, --output <file>` | Save a JSON report | — |
| `--json` | Print the JSON report to stdout (suppresses formatted output) | off |
| `-v, --verbose` | Log each file scanned | off |

GitHub Code Search requires authentication for most queries. If you hit a rate limit, the tool prints the reset time. **Use this command only to find your own leaked secrets or secrets you intend to responsibly disclose to the affected owner.**

#### `--all` — scan with every built-in pattern

Instead of supplying a query, pass `--all` to scan GitHub the same way the website scanner works — against the full pattern set:

```bash
keyscanner github --all --token "$GITHUB_TOKEN"
keyscanner github --all --max 5 --json
```

How it works: GitHub's Code Search API always requires a query string, so `--all` takes the distinctive literal seed defined on each pattern (e.g. `AIzaSy`, `sk_live_`, `ghp_`, `sk-ant-`) and runs **one search per seed**. Every file returned by any search is then fetched and checked against **all** patterns (not just the one that surfaced it), and findings for the same file are merged and de-duplicated.

Notes:
- `--all` runs ~14 searches, so a `--token` is strongly recommended — unauthenticated requests are blocked/rate-limited almost immediately. If a rate limit is hit mid-run, the tool stops early and returns the partial results gathered so far.
- `--max` becomes the file budget **per seed**.
- 14 of the 21 patterns have search seeds; patterns without a distinctive literal (generic secrets, bearer tokens, contextual AWS/Twilio matches) can't seed a search, but they are still applied to every file that is fetched.

### `bulk` — scan many sites

```bash
keyscanner bulk sites.txt
keyscanner bulk sites.txt -o reports/ --csv all-findings.csv -c 4
```

Where `sites.txt` has one URL per line (blank lines and `#` comments ignored).

| Option | Description | Default |
| --- | --- | --- |
| `-o, --output <dir>` | Directory for per-site JSON reports | — |
| `--csv <file>` | Aggregate CSV of all findings | — |
| `-c, --concurrency <n>` | Sites scanned in parallel | `2` |
| `-t, --timeout <ms>` | Per-request timeout | `10000` |
| `-v, --verbose` | Log each file scanned | off |

Prints a summary table (`site | findings | crit | high | med`) at the end and exits `1` if any critical finding is detected.

## Detected key types

| Key type | Severity |
| --- | --- |
| Google API Key (`AIza…`) | critical |
| AWS Access Key ID (`AKIA…`) | critical |
| AWS Secret Access Key | critical |
| Stripe Live Secret Key (`sk_live_…`) | critical |
| Stripe Live Public Key (`pk_live_…`) | high |
| GitHub Personal Access Token (`ghp_…`) | critical |
| GitHub OAuth Token (`gho_…`) | critical |
| Slack Token (`xoxb-`, `xoxa-`, …) | high |
| Firebase Project URL (`*.firebaseio.com`) | medium |
| Firebase API Config Block | high |
| Twilio Account SID (`AC…`) | critical |
| Twilio Auth Token | critical |
| SendGrid API Key (`SG.…`) | critical |
| Mailgun API Key (`key-…`) | high |
| JWT Token (`eyJ…`) | medium |
| OpenAI API Key (`sk-…`) | critical |
| Anthropic API Key (`sk-ant-…`) | critical |
| HuggingFace Token (`hf_…`) | high |
| Mapbox Token (`pk.eyJ1…`) | high |
| Bearer Token in JS string | medium |
| Generic Hardcoded Secret (`apiKey`/`secret`/`token`/`password` = 16+ chars) | medium |

Patterns are heuristic: false positives happen, and the absence of a finding is **not** proof a site is clean. Always verify by hand.

## Responsible disclosure

> **Always report findings, never exploit them.**

If you discover an exposed secret that is not yours:

1. Do **not** use, test, or validate the key against any live service.
2. Notify the owner privately (security contact, `security.txt`, or a coordinated-disclosure platform).
3. Give them reasonable time to rotate the credential before any public mention.

If the key is yours: rotate it immediately, then audit logs for misuse.

## Legal disclaimer

This tool is provided for **authorized security testing, defensive security, and educational research only**. You are responsible for ensuring you have permission to scan any target. Scanning systems you do not own or are not explicitly authorized to test may violate the U.S. Computer Fraud and Abuse Act, the UK Computer Misuse Act, and equivalent laws in other jurisdictions. The authors accept no liability for misuse. By using `keyscanner` you agree to use it lawfully and ethically.

## License

MIT
