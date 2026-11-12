// Rule tests for the merged sanitizer items of rules/javascript-web.yaml (R-008). A
// sanitizer item that ends in the same bare `pattern: $X` is merged with its siblings
// into one item. Each handler below carries one alternative of such an item and the
// guard is accepted (ok); the controls at the end are the same handlers without a
// guard. Guard shapes the rule still reports with this instantiation are left out.
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
  const u = String(req.query.u);
  if (!ALLOWED_HOSTS.has(u.hostname)) { return res.status(400).end(); }
  // ok: js-ssrf-taint
  await fetch(u);
  res.end();
});

router.get("/gen/2", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (flag || !ALLOWED_HOSTS.has(u.hostname)) { return res.status(400).end(); }
  // ok: js-ssrf-taint
  await fetch(u);
  res.end();
});

router.get("/gen/3", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (!ALLOWED_HOSTS.has(u.hostname) || flag) { return res.status(400).end(); }
  // ok: js-ssrf-taint
  await fetch(u);
  res.end();
});

router.get("/gen/4", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (!ALLOWED_HOSTS.has(new URL(u).hostname)) { return res.status(400).end(); }
  // ok: js-ssrf-taint
  await fetch(u);
  res.end();
});

router.get("/gen/5", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (flag || !ALLOWED_HOSTS.has(new URL(u).hostname)) { return res.status(400).end(); }
  // ok: js-ssrf-taint
  await fetch(u);
  res.end();
});

router.get("/gen/6", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (!ALLOWED_HOSTS.has(new URL(u).hostname) || flag) { return res.status(400).end(); }
  // ok: js-ssrf-taint
  await fetch(u);
  res.end();
});

router.get("/gen/7", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  parsed = new URL(u);
  if (!ALLOWED_HOSTS.has(parsed.hostname)) { return res.status(400).end(); }
  // ok: js-ssrf-taint
  await fetch(u);
  res.end();
});

router.get("/gen/8", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  parsed = new URL(u);
  if (flag || !ALLOWED_HOSTS.has(parsed.hostname)) { return res.status(400).end(); }
  // ok: js-ssrf-taint
  await fetch(u);
  res.end();
});

router.get("/gen/9", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  parsed = new URL(u);
  if (!ALLOWED_HOSTS.has(parsed.hostname) || flag) { return res.status(400).end(); }
  // ok: js-ssrf-taint
  await fetch(u);
  res.end();
});

router.get("/gen/10", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  const {..., hostname, ...} = new URL(u);
  if (!ALLOWED_HOSTS.has(hostname)) { return res.status(400).end(); }
  // ok: js-ssrf-taint
  await fetch(u);
  res.end();
});

router.get("/gen/11", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  const {..., hostname, ...} = new URL(u);
  if (flag || !ALLOWED_HOSTS.has(hostname)) { return res.status(400).end(); }
  // ok: js-ssrf-taint
  await fetch(u);
  res.end();
});

router.get("/gen/12", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  const {..., hostname, ...} = new URL(u);
  if (!ALLOWED_HOSTS.has(hostname) || flag) { return res.status(400).end(); }
  // ok: js-ssrf-taint
  await fetch(u);
  res.end();
});

router.get("/gen/13", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (ALLOWED_HOSTS.has(u.hostname)) {
   // ok: js-ssrf-taint
   await fetch(u);
   }
  
  res.end();
});

router.get("/gen/14", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (ALLOWED_HOSTS.has(new URL(u).hostname)) {
   // ok: js-ssrf-taint
   await fetch(u);
   }
  
  res.end();
});

router.get("/gen/31", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const p = String(req.query.p);
  rel = path.relative(UPLOAD_DIR, p);
  if (rel.startsWith("..") || path.isAbsolute(rel)) { return res.status(400).end(); }
  // ok: js-path-traversal-taint
  await fsp.readFile(p, 'utf8');
  res.end();
});

router.get("/gen/32", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const p = String(req.query.p);
  rel = path.relative(UPLOAD_DIR, p);
  if (rel.startsWith("..") || path.isAbsolute(rel) || flag) { return res.status(400).end(); }
  // ok: js-path-traversal-taint
  await fsp.readFile(p, 'utf8');
  res.end();
});

router.get("/gen/33", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const p = String(req.query.p);
  rel = path.relative(UPLOAD_DIR, p);
  if (flag || rel.startsWith("..") || path.isAbsolute(rel)) { return res.status(400).end(); }
  // ok: js-path-traversal-taint
  await fsp.readFile(p, 'utf8');
  res.end();
});

router.get("/gen/34", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const p = String(req.query.p);
  rel = path.relative(UPLOAD_DIR, p);
  if (flag || (rel.startsWith("..") || path.isAbsolute(rel))) { return res.status(400).end(); }
  // ok: js-path-traversal-taint
  await fsp.readFile(p, 'utf8');
  res.end();
});

router.get("/gen/35", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const p = String(req.query.p);
  rel = path.relative(UPLOAD_DIR, p);
  if (path.isAbsolute(rel) || rel.startsWith("..")) { return res.status(400).end(); }
  // ok: js-path-traversal-taint
  await fsp.readFile(p, 'utf8');
  res.end();
});

router.get("/gen/36", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const p = String(req.query.p);
  rel = path.relative(UPLOAD_DIR, p);
  if (path.isAbsolute(rel) || rel.startsWith("..") || flag) { return res.status(400).end(); }
  // ok: js-path-traversal-taint
  await fsp.readFile(p, 'utf8');
  res.end();
});

router.get("/gen/37", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const p = String(req.query.p);
  rel = path.relative(UPLOAD_DIR, p);
  if (flag || path.isAbsolute(rel) || rel.startsWith("..")) { return res.status(400).end(); }
  // ok: js-path-traversal-taint
  await fsp.readFile(p, 'utf8');
  res.end();
});

router.get("/gen/38", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const p = String(req.query.p);
  rel = path.relative(UPLOAD_DIR, p);
  if (flag || (path.isAbsolute(rel) || rel.startsWith(".."))) { return res.status(400).end(); }
  // ok: js-path-traversal-taint
  await fsp.readFile(p, 'utf8');
  res.end();
});

router.get("/gen/39", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (!u.startsWith("/") || u.startsWith("//")) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/40", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (!u.startsWith("/") || u.startsWith("//") || flag) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/41", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (flag || !u.startsWith("/") || u.startsWith("//")) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/42", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (flag || (!u.startsWith("/") || u.startsWith("//"))) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/43", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (u.startsWith("//") || !u.startsWith("/")) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/44", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (u.startsWith("//") || !u.startsWith("/") || flag) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/45", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (flag || u.startsWith("//") || !u.startsWith("/")) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/46", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (flag || (u.startsWith("//") || !u.startsWith("/"))) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/47", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (!ALLOWED_HOSTS.has(u.hostname)) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/48", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (flag || !ALLOWED_HOSTS.has(u.hostname)) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/49", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (!ALLOWED_HOSTS.has(u.hostname) || flag) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/50", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (!ALLOWED_HOSTS.has(new URL(u).hostname)) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/51", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (flag || !ALLOWED_HOSTS.has(new URL(u).hostname)) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/52", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (!ALLOWED_HOSTS.has(new URL(u).hostname) || flag) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/53", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  parsed = new URL(u);
  if (!ALLOWED_HOSTS.has(parsed.hostname)) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/54", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  parsed = new URL(u);
  if (flag || !ALLOWED_HOSTS.has(parsed.hostname)) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/55", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  parsed = new URL(u);
  if (!ALLOWED_HOSTS.has(parsed.hostname) || flag) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/56", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  const {..., hostname, ...} = new URL(u);
  if (!ALLOWED_HOSTS.has(hostname)) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/57", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  const {..., hostname, ...} = new URL(u);
  if (flag || !ALLOWED_HOSTS.has(hostname)) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/58", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  const {..., hostname, ...} = new URL(u);
  if (!ALLOWED_HOSTS.has(hostname) || flag) { return res.status(400).end(); }
  // ok: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

router.get("/gen/59", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (ALLOWED_HOSTS.has(u.hostname)) {
   // ok: js-open-redirect-taint
   res.redirect(u);
   }
  
  res.end();
});

router.get("/gen/60", async (req, res) => {
  const flag = Boolean(req.query.flag);
  const u = String(req.query.u);
  if (ALLOWED_HOSTS.has(new URL(u).hostname)) {
   // ok: js-open-redirect-taint
   res.redirect(u);
   }
  
  res.end();
});

// Control: the same handler without a guard is a finding.
router.get("/gen/control/js-open-redirect-taint", async (req, res) => {
  const u = String(req.query.u);
  // ruleid: js-open-redirect-taint
  res.redirect(u);
  res.end();
});

// Control: the same handler without a guard is a finding.
router.get("/gen/control/js-path-traversal-taint", async (req, res) => {
  const p = String(req.query.p);
  // ruleid: js-path-traversal-taint
  await fsp.readFile(p, 'utf8');
  res.end();
});

// Control: the same handler without a guard is a finding.
router.get("/gen/control/js-ssrf-taint", async (req, res) => {
  const u = String(req.query.u);
  // ruleid: js-ssrf-taint
  await fetch(u);
  res.end();
});
