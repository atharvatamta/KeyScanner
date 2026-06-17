// Tiny static server for manual CLI testing. Serves a page with planted
// FAKE secrets on the port given as argv[2] (default 8799).
import http from 'node:http';

const port = Number(process.argv[2]) || 8799;
const js = `
const config = { apiKey: "AIzaSyD-FAKE_dummy_key_000000000000000000", authDomain: "x.firebaseapp.com" };
const stripe = "sk_live_FAKE000000000000000000000000";
const gh = "ghp_FAKE0000000000000000000000000000000000";
`;
const html = `<!doctype html><html><body><script>${js}</script>
<script src="/app.js"></script></body></html>`;
const appJs = `const aws="AKIAFAKE0000000000AB"; const t="sk-ant-FAKE000000000000000000anthropic";`;

http
  .createServer((req, res) => {
    if (req.url === '/app.js') {
      res.setHeader('Content-Type', 'application/javascript');
      res.end(appJs);
    } else {
      res.setHeader('Content-Type', 'text/html');
      res.end(html);
    }
  })
  .listen(port, () => console.log(`serving on ${port}`));
