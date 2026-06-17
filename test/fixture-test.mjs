// Quick self-test: plant fake secrets, confirm the scanner detects them.
// All values below are INVALID dummy strings — not real credentials.
import http from 'node:http';
import { scanUrl } from '../src/scanner.js';
import { scanContent } from '../src/scanner.js';

const fixtureJs = `
const config = {
  apiKey: "AIzaSyD-FAKE_dummy_key_000000000000000000",
  authDomain: "demo-app.firebaseapp.com",
  databaseURL: "https://demo-app.firebaseio.com",
};
const stripe = "sk_live_FAKE000000000000000000000000";
const aws = "AKIAFAKE0000000000AB";
const gh = "ghp_FAKE0000000000000000000000000000000000";
const openai = "sk-FAKE000000000000000000openai00000";
const anthropic = "sk-ant-FAKE000000000000000000anthropic";
const password = "supersecretpassword1234";
fetch(url, { headers: { Authorization: "Bearer FAKEabcdefghij1234567890token" } });
`;

console.log('--- scanContent direct test ---');
const findings = scanContent(fixtureJs, 'fixture.js');
for (const f of findings) {
  console.log(`[${f.severity}] ${f.type} -> ${f.match} (line ${f.lineNumber})`);
}
console.log(`Total: ${findings.length} findings\n`);

// End-to-end: serve an HTML page that references an inline script.
const html = `<!doctype html><html><head><title>t</title></head>
<body><script>${fixtureJs}</script></body></html>`;

const server = http.createServer((req, res) => {
  res.setHeader('Content-Type', 'text/html');
  res.end(html);
});

await new Promise((resolve) => server.listen(0, resolve));
const port = server.address().port;
const url = `http://127.0.0.1:${port}/`;

console.log(`--- end-to-end scanUrl(${url}) ---`);
const result = await scanUrl(url, { verbose: false });
console.log(`scannedFiles=${result.scannedFiles}, findings=${result.findings.length}`);
const criticals = result.findings.filter((f) => f.severity === 'critical');
console.log(`critical findings: ${criticals.map((f) => f.type).join(', ')}`);

server.close();

if (findings.length < 8 || criticals.length < 4) {
  console.error('\nFAIL: expected more detections.');
  process.exit(1);
}
console.log('\nPASS');
