
// Generated: one handler per alternative of a merged sanitizer item.
import express from 'express';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';
import { Pool } from 'pg';

const router = express.Router();
const pool = new Pool();
const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');
const ALLOWED_HOSTS = new Set(['api.github.com', 'cdn.example.com']);
const ALLOWED_SORTS = new Set(['id', 'name']);


router.get("/gen/1", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const v = String(req.query.sort);
  if (!ALLOWED_SORTS.has(v)) { return res.status(400).end(); }
  const q = "SELECT id FROM t ORDER BY " + v;
  // ok: js-sqli-taint
  await pool.query(q);
  res.end();
});

router.get("/gen/2", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const v = String(req.query.sort);
  if (flag || !ALLOWED_SORTS.has(v)) { return res.status(400).end(); }
  const q = "SELECT id FROM t ORDER BY " + v;
  // ok: js-sqli-taint
  await pool.query(q);
  res.end();
});

router.get("/gen/3", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const v = String(req.query.sort);
  if (!ALLOWED_SORTS.has(v) || flag) { return res.status(400).end(); }
  const q = "SELECT id FROM t ORDER BY " + v;
  // ok: js-sqli-taint
  await pool.query(q);
  res.end();
});

router.get("/gen/4", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const v = String(req.query.sort);
  if (!ALLOWED_SORTS.has(v)) v = "id";
  const q = "SELECT id FROM t ORDER BY " + v;
  // ok: js-sqli-taint
  await pool.query(q);
  res.end();
});

router.get("/gen/5", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const v = String(req.query.sort);
  if (flag || !ALLOWED_SORTS.has(v)) v = "id";
  const q = "SELECT id FROM t ORDER BY " + v;
  // ok: js-sqli-taint
  await pool.query(q);
  res.end();
});

router.get("/gen/6", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const v = String(req.query.sort);
  if (!ALLOWED_SORTS.has(v) || flag) v = "id";
  const q = "SELECT id FROM t ORDER BY " + v;
  // ok: js-sqli-taint
  await pool.query(q);
  res.end();
});

router.get("/gen/7", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const v = String(req.query.sort);
  if (!ALLOWED_SORTS.has(v)) {
    v = "id";
  }
  const q = "SELECT id FROM t ORDER BY " + v;
  // ok: js-sqli-taint
  await pool.query(q);
  res.end();
});

router.get("/gen/8", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const v = String(req.query.sort);
  if (flag || !ALLOWED_SORTS.has(v)) {
    v = "id";
  }
  const q = "SELECT id FROM t ORDER BY " + v;
  // ok: js-sqli-taint
  await pool.query(q);
  res.end();
});

router.get("/gen/9", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const v = String(req.query.sort);
  if (!ALLOWED_SORTS.has(v) || flag) {
    v = "id";
  }
  const q = "SELECT id FROM t ORDER BY " + v;
  // ok: js-sqli-taint
  await pool.query(q);
  res.end();
});

// Control: the same handler without a guard is a finding.
router.get("/gen/control/js-sqli-taint", async (req, res) => {
  const v = String(req.query.sort);
  const q = "SELECT id FROM t ORDER BY " + v;
  // ruleid: js-sqli-taint
  await pool.query(q);
  res.end();
});
