// @flow
// Rule tests for rules/javascript-injection.yaml on JavaScript that uses Flow's
// `as` cast (Flow 0.229+). The value is destructured from a cast request value,
// the shape the `const {..., $V, ...} = $E as $T` source of each taint rule
// reads. These lines are .js files, so they pin what the JavaScript flavour of
// the pack must still report if the TypeScript-only source items are moved out
// of it. See README.md for the annotation format.

import { exec } from 'node:child_process';
import ejs from 'ejs';
import { Pool } from 'pg';

const pool = new Pool();

export async function lookupUser(req, res) {
  const { id } = (req.body as { id: string });
  // ruleid: js-sqli-taint, js-sqli-sink
  const rows = await pool.query(`SELECT * FROM users WHERE id = ${id}`);
  // ok: js-sqli-taint
  const safe = await pool.query('SELECT * FROM users WHERE id = $1', [id]);
  res.json({ rows, safe });
}

export async function POST(request) {
  const { host } = (await request.json()) as { host: string };
  // ruleid: js-cmdi-taint, js-cmdi-sink
  exec('ping -c 1 ' + host, () => undefined);
  // ok: js-cmdi-taint
  exec('ping -c 1 localhost', () => undefined);
  return host;
}

export async function PUT(request) {
  const { template } = (await request.json()) as { template: string };
  // ruleid: js-ssti-taint
  const html = ejs.render(template, { year: 2026 });
  // ok: js-ssti-taint
  const fixed = ejs.render('<p><%= year %></p>', { year: 2026 });
  return html + fixed;
}
