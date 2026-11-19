// Rule tests for rules/javascript-injection.yaml: drizzle's sql tag binds its
// interpolations (Review Focus 1); its sql.raw(...) does not. See README.md for
// the annotation format.

import { sql } from 'drizzle-orm';
import express from 'express';

const router = express.Router();
const db: any = {};

router.get('/users/:id', async (req, res) => {
  const id = req.params.id;
  // ok: js-sqli-taint, js-sqli-sink
  const a = await db.execute(sql`SELECT * FROM users WHERE id = ${id}`);
  // ruleid: js-sqli-taint, js-sqli-sink
  const b = await db.execute(sql.raw(`SELECT * FROM users WHERE id = ${id}`));
  res.json({ a, b });
});

export { router };
