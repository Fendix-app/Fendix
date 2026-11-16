// @flow
// Rule tests for rules/javascript-web.yaml on JavaScript that uses Flow's `as`
// cast (Flow 0.229+): the `const {..., $V, ...} = $E as $T` source of each
// taint rule, in a .js file. See javascript-injection.flow-as.js.

import * as fsp from 'node:fs/promises';
import * as path from 'node:path';

const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');

export function search(req, res) {
  const { q } = (req.query as { q: string });
  // ruleid: js-xss-taint
  res.send(`<h1>Search results for ${q}</h1>`);
  // ok: js-xss-taint
  res.send('<h1>Search</h1>');
}

export async function preview(req, res) {
  const { url } = (req.body as { url: string });
  // ruleid: js-ssrf-taint
  const upstream = await fetch(url);
  // ok: js-ssrf-taint
  const status = await fetch('https://status.example.com/api/v2/status.json');
  res.json({ a: upstream.status, b: status.status });
}

export async function download(req, res) {
  const { file } = (req.query as { file: string });
  // ruleid: js-path-traversal-taint
  const content = await fsp.readFile(path.join(UPLOAD_DIR, file), 'utf8');
  // ok: js-path-traversal-taint
  const readme = await fsp.readFile(path.join(UPLOAD_DIR, 'README.txt'), 'utf8');
  res.send(content + readme);
}

export function login(req, res) {
  const { returnTo } = (req.query as { returnTo: string });
  // ruleid: js-open-redirect-taint
  res.redirect(returnTo);
  // ok: js-open-redirect-taint
  res.redirect('/home');
}
