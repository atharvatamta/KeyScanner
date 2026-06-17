/**
 * Regex patterns used to detect exposed secrets/API keys.
 *
 * Each entry is: { name, regex, severity, search? }
 *   - name:     human readable label shown in reports
 *   - regex:    a /g regular expression (REQUIRED: global flag so we can
 *               iterate over every match in a file)
 *   - severity: "critical" | "high" | "medium"
 *   - search:   (optional) a distinctive literal usable as a GitHub Code
 *               Search seed. Used by `keyscanner github --all` to surface
 *               candidate files. Patterns without a useful literal (generic
 *               secrets, bearer tokens, contextual AWS/Twilio matches) omit
 *               it and are still applied to every file that IS fetched.
 *
 * These patterns are intentionally conservative. False positives are
 * possible (especially the generic ones) and every finding should be
 * verified by a human before any action is taken.
 */

export const patterns = [
  {
    name: 'Google API Key',
    regex: /AIza[0-9A-Za-z\-_]{35}/g,
    severity: 'critical',
    search: 'AIzaSy',
  },
  {
    name: 'AWS Access Key ID',
    regex: /\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA)[0-9A-Z]{16}\b/g,
    severity: 'critical',
    search: 'AKIA',
  },
  {
    name: 'AWS Secret Access Key',
    // Contextual: an aws*secret-ish assignment near a 40-char base64-style value.
    regex: /aws(.{0,25})?(secret|sk)(.{0,25})?['"][0-9a-zA-Z/+=]{40}['"]/gi,
    severity: 'critical',
  },
  {
    name: 'Stripe Live Secret Key',
    regex: /sk_live_[0-9a-zA-Z]{24,}/g,
    severity: 'critical',
    search: 'sk_live_',
  },
  {
    name: 'Stripe Live Public Key',
    regex: /pk_live_[0-9a-zA-Z]{24,}/g,
    severity: 'high',
    search: 'pk_live_',
  },
  {
    name: 'GitHub Personal Access Token',
    regex: /ghp_[0-9A-Za-z]{36}/g,
    severity: 'critical',
    search: 'ghp_',
  },
  {
    name: 'GitHub OAuth Token',
    regex: /gho_[0-9A-Za-z]{36}/g,
    severity: 'critical',
    search: 'gho_',
  },
  {
    name: 'Slack Token',
    regex: /xox[abprs]-[0-9A-Za-z-]{10,}/g,
    severity: 'high',
    search: 'xoxb-',
  },
  {
    name: 'Firebase Project URL',
    regex: /[a-z0-9-]+\.firebaseio\.com/g,
    severity: 'medium',
    search: 'firebaseio.com',
  },
  {
    name: 'Firebase API Config Block',
    // Catches a firebase config object: an apiKey alongside an authDomain /
    // databaseURL / projectId field.
    regex: /(?:authDomain|databaseURL|storageBucket|messagingSenderId)['"]?\s*:\s*['"][^'"]*firebase[^'"]*['"]/gi,
    severity: 'high',
  },
  {
    name: 'Twilio Account SID',
    regex: /\bAC[0-9a-fA-F]{32}\b/g,
    severity: 'critical',
  },
  {
    name: 'Twilio Auth Token',
    regex: /twilio(.{0,25})?(auth|token)(.{0,25})?['"][0-9a-fA-F]{32}['"]/gi,
    severity: 'critical',
  },
  {
    name: 'SendGrid API Key',
    regex: /SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}/g,
    severity: 'critical',
    search: 'SG.',
  },
  {
    name: 'Mailgun API Key',
    regex: /key-[0-9a-zA-Z]{32}/g,
    severity: 'high',
  },
  {
    name: 'JWT Token',
    regex: /eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g,
    severity: 'medium',
    search: 'eyJhbG',
  },
  {
    name: 'OpenAI API Key',
    // sk- but not sk-ant- (Anthropic) — handled separately below.
    regex: /sk-(?!ant-)(?:proj-)?[A-Za-z0-9_-]{20,}/g,
    severity: 'critical',
    search: 'sk-proj-',
  },
  {
    name: 'Anthropic API Key',
    regex: /sk-ant-[A-Za-z0-9_-]{20,}/g,
    severity: 'critical',
    search: 'sk-ant-',
  },
  {
    name: 'HuggingFace Token',
    regex: /hf_[A-Za-z0-9]{34,}/g,
    severity: 'high',
    search: 'hf_',
  },
  {
    name: 'Mapbox Token',
    regex: /pk\.eyJ1[A-Za-z0-9._-]{20,}/g,
    severity: 'high',
    search: 'pk.eyJ1',
  },
  {
    name: 'Bearer Token',
    regex: /[Bb]earer\s+[A-Za-z0-9\-._~+/]{20,}={0,2}/g,
    severity: 'medium',
  },
  {
    name: 'Generic Hardcoded Secret',
    // A variable named apiKey/api_key/secret/token/password assigned a
    // string literal of 16+ characters.
    regex: /(?:api[_-]?key|secret|token|password|passwd|pwd)['"]?\s*[:=]\s*['"]([^'"]{16,})['"]/gi,
    severity: 'medium',
  },
];

export default patterns;
