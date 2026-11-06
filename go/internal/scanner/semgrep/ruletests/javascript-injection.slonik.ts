// Rule tests for rules/javascript-injection.yaml: slonik's tagged templates,
// imported as sql the way slonik's documentation does. Every one binds its
// interpolations (Review Focus 1). See README.md for the annotation format.

import express from 'express';
import { createPool, sql } from 'slonik';

const router = express.Router();

router.get('/users/:id', async (req, res) => {
  const pool = await createPool(String(process.env.DATABASE_URL));
  const id = req.params.id;
  // ok: js-sqli-taint, js-sqli-sink
  const a = await pool.query(sql`SELECT * FROM users WHERE id = ${id}`);
  // ok: js-sqli-taint, js-sqli-sink
  const b = await pool.query(sql.type(User)`SELECT * FROM users WHERE id = ${id}`);
  // ok: js-sqli-taint, js-sqli-sink
  const c = await pool.query(sql.unsafe`SELECT * FROM users WHERE id = ${id}`);
  // ok: js-sqli-taint, js-sqli-sink
  const d = await pool.query(sql.typeAlias('id')`SELECT id FROM users WHERE id = ${id}`);
  // ok: js-sqli-taint, js-sqli-sink
  const e = await pool.query(sql.fragment`WHERE id = ${id}`);
  // An untagged template is plain string building, slonik or not.
  // ruleid: js-sqli-taint, js-sqli-sink
  const f = await pool.query(`SELECT * FROM users WHERE id = ${id}`);
  res.json({ a, b, c, d, e, f });
});

export { router };
