// Rule tests for rules/javascript-web.yaml: cross-site scripting, SSRF, path
// traversal and open redirect, in the Express, NestJS and Next.js idioms. See
// README.md for the annotation format.

import { BadRequestException, Controller, Get, Query, Res } from '@nestjs/common';
import axios from 'axios';
import DOMPurify from 'dompurify';
import escapeHtml from 'escape-html';
import express, { Response } from 'express';
import got from 'got';
import he from 'he';
import ejs from 'ejs';
import _ from 'lodash';
import nunjucks from 'nunjucks';
import { renderToString } from 'react-dom/server';
import { NextRequest, NextResponse } from 'next/server';
import * as fs from 'node:fs';
import * as fsp from 'node:fs/promises';
import * as https from 'node:https';
import * as path from 'node:path';
import { request as undiciRequest } from 'undici';

const router = express.Router();

const SITE_NAME = 'Acme Docs';
const STATUS_URL = 'https://status.example.com/api/v2/status.json';
const LOGIN_URL = 'https://accounts.example.com/login';
const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');
const ALLOWED_HOSTS = new Set(['api.github.com', 'cdn.example.com']);
const BLOCKED_HOSTS = new Set(['169.254.169.254', 'localhost']);
const PUBLIC_DIR = path.join(__dirname, 'public');
const RAW_ROW = '<tr><td><%- q %></td></tr>';
const ESCAPED_ROW = '<tr><td><%= q %></td></tr>';

// ---------------------------------------------------------------------------
// Cross-site scripting
// ---------------------------------------------------------------------------

router.get('/xss/express', (req, res) => {
  const q = req.query.q;
  // ruleid: js-xss-taint
  res.send(`<h1>Search results for ${q}</h1>`);
  // ruleid: js-xss-taint
  res.write('<p>' + req.query.note + '</p>');
  // ok: js-xss-taint
  res.send(`<h1>Search results for ${escapeHtml(q)}</h1>`);
  // ok: js-xss-taint
  res.send(`<h1>${he.encode(String(q))}</h1>`);
  // ok: js-xss-taint
  res.send(DOMPurify.sanitize(`<p>${q}</p>`));
  // ok: js-xss-taint
  res.send(`<a href="/search?q=${encodeURIComponent(String(q))}">again</a>`);
  // ok: js-xss-taint
  res.send(`<h1>Welcome to ${SITE_NAME}</h1>`);
  // ok: js-xss-taint
  res.json({ q });
});

// Helpers whose parameter is written into the markup: only the shape rule
// sees them.
function renderResults(res: Response, q: string) {
  // ruleid: js-xss-sink
  res.send(`<h1>Search results for ${q}</h1>`);
}

function renderPage(q: string): Response {
  // ruleid: js-xss-sink
  return new Response('<p>' + q + '</p>', { headers: { 'Content-Type': 'text/html' } });
}

function renderSafe(res: Response, q: string, count: number) {
  // ok: js-xss-sink
  res.send(`<h1>${escapeHtml(q)}</h1>`);
  // ok: js-xss-sink
  res.send(`<h1>Welcome to ${SITE_NAME}</h1>`);
  // ok: js-xss-sink
  res.send(`Search results for ${q}`);
  // ok: js-xss-sink
  return new Response(`<p>${q}</p>`, { headers: { 'Content-Type': 'application/json' } });
}

// A decoder, or an escaper for another language, is not an HTML sanitiser.
router.get('/xss/decoders', (req, res) => {
  const q = String(req.query.q);
  // ruleid: js-xss-taint
  res.send('<p>' + unescape(q) + '</p>');
  // ruleid: js-xss-taint
  res.send('<p>' + _.unescape(q) + '</p>');
  // ruleid: js-xss-taint
  res.send('<p>' + he.decode(q) + '</p>');
  // ruleid: js-xss-taint
  res.send('<p>' + _.escapeRegExp(q) + '</p>');
  // ok: js-xss-taint
  res.send(`<a href='/x?q=${encodeURI(q)}'>x</a>`);
  // ok: js-xss-taint
  res.send('<p>' + _.escape(q) + '</p>');
});

// The output of an autoescaping template rendered from a fixed template is
// escaped already; a template taken from the request is SSTI, not this.
router.get('/xss/rendered', async (req, res) => {
  if (req.query.engine === 'nunjucks') {
    const html = nunjucks.render('page.njk', { q: req.query.q });
    // ok: js-xss-taint
    return res.send(html);
  }
  if (req.query.engine === 'ejs') {
    const html = await ejs.renderFile('views/page.ejs', { q: req.query.q });
    // ok: js-xss-taint
    return res.send(html);
  }
  if (req.query.engine === 'react') {
    const html = renderToString(Page({ q: req.query.q }));
    // ok: js-xss-taint
    return res.send(html);
  }
  const html = nunjucks.renderString(String(req.query.tpl), {});
  // ruleid: js-xss-taint
  res.send(html);
});

// A fixed template that writes the value raw is not escaped output: ejs <%-,
// Mustache and Handlebars {{{ }}}, nunjucks | safe, pug !=.
router.get('/xss/raw-templates', (req, res) => {
  const q = req.query.q;
  if (q === 'ejs') {
    const html = ejs.render('<p><%- q %></p>', { q: req.query.q });
    // ruleid: js-xss-taint
    return res.send(html);
  }
  if (q === 'nunjucks') {
    const html = nunjucks.renderString('<p>{{ q | safe }}</p>', { q: req.query.q });
    // ruleid: js-xss-taint
    return res.send(html);
  }
  if (q === 'const') {
    const html = ejs.render(RAW_ROW, { q: req.query.q });
    // ruleid: js-xss-taint
    return res.send(html);
  }
  const html = ejs.render(ESCAPED_ROW, { q: req.query.q });
  // ok: js-xss-taint
  res.send(html);
});

@Controller('xss')
export class XssController {
  @Get()
  search(@Query('q') q: string, @Res() res: Response) {
    // ruleid: js-xss-taint, js-xss-sink
    res.send(`<h1>Search results for ${q}</h1>`);
  }

  @Get('safe')
  searchSafe(@Query('q') q: string, @Res() res: Response) {
    // ok: js-xss-taint
    res.send(`<h1>Search results for ${escapeHtml(q)}</h1>`);
  }
}

export function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams.get('q') ?? '';
  if (q === 'plain') {
    // ok: js-xss-taint
    return new Response(`Search results for ${q}`, { headers: { 'Content-Type': 'text/plain' } });
  }
  if (q === 'safe') {
    // ok: js-xss-taint
    return new Response(`<h1>${escapeHtml(q)}</h1>`, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
  }
  if (q === 'next') {
    // ruleid: js-xss-taint
    return new NextResponse(`<h1>Search results for ${q}</h1>`, { headers: { 'Content-Type': 'text/html' } });
  }
  // ruleid: js-xss-taint
  return new Response(`<h1>Search results for ${q}</h1>`, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

// ---------------------------------------------------------------------------
// Server-side request forgery
// ---------------------------------------------------------------------------

router.get('/ssrf/express', async (req, res) => {
  const url = req.query.url;
  // ruleid: js-ssrf-taint
  const upstream = await fetch(url);
  // ruleid: js-ssrf-taint
  await axios.get(url, { responseType: 'text' });
  // ruleid: js-ssrf-taint
  await axios({ url: req.query.target });
  // ruleid: js-ssrf-taint
  await got(req.query.feed);
  // ruleid: js-ssrf-taint
  https.get(req.query.image, () => undefined);
  // ruleid: js-ssrf-taint
  await undiciRequest(req.query.hook);
  // ok: js-ssrf-taint
  await fetch(STATUS_URL);
  res.json({ status: upstream.status });
});

router.get('/ssrf/allowlist', async (req, res) => {
  const url = req.query.url;
  let target;
  try {
    target = new URL(url);
  } catch {
    return res.status(400).json({ error: 'Invalid URL' });
  }
  if (target.protocol !== 'https:' || !ALLOWED_HOSTS.has(target.hostname)) {
    return res.status(400).json({ error: 'Host not allowed' });
  }
  // ok: js-ssrf-taint
  const upstream = await fetch(target);
  res.json({ status: upstream.status });
});

router.get('/ssrf/allowlist-inline', async (req, res) => {
  const url = String(req.query.url);
  if (!ALLOWED_HOSTS.has(new URL(url).hostname)) {
    return res.status(400).end();
  }
  // ok: js-ssrf-taint
  const upstream = await fetch(url);
  res.json({ status: upstream.status });
});

router.get('/ssrf/allowlist-braceless', async (req, res) => {
  const url = String(req.query.url);
  if (!ALLOWED_HOSTS.has(new URL(url).hostname)) return res.status(400).end();
  // ok: js-ssrf-taint
  const upstream = await fetch(url);
  res.json({ status: upstream.status });
});

// The allowlist checks the URL the string parses to; the string is clean too.
router.get('/ssrf/allowlist-parsed', async (req, res) => {
  const url = String(req.query.url);
  const parsed = new URL(url);
  if (!ALLOWED_HOSTS.has(parsed.hostname)) return res.status(400).end();
  // ok: js-ssrf-taint
  const upstream = await fetch(url);
  res.json({ status: upstream.status });
});

router.get('/ssrf/allowlist-destructured', async (req, res) => {
  const url = String(req.query.url);
  const { hostname } = new URL(url);
  if (!ALLOWED_HOSTS.has(hostname)) return res.status(400).end();
  // ok: js-ssrf-taint
  const upstream = await fetch(url);
  res.json({ status: upstream.status });
});

// A denylist is not an allowlist, and a check that does not leave is no check.
router.get('/ssrf/denylist', async (req, res) => {
  const u = new URL(String(req.query.url));
  if (BLOCKED_HOSTS.has(u.hostname)) return res.status(400).end();
  // ruleid: js-ssrf-taint
  const upstream = await fetch(u);
  res.json({ status: upstream.status });
});

router.get('/ssrf/allowlist-log-only', async (req, res) => {
  const u = new URL(String(req.query.url));
  if (!ALLOWED_HOSTS.has(u.hostname)) console.warn('unknown host');
  // ruleid: js-ssrf-taint
  const upstream = await fetch(u);
  res.json({ status: upstream.status });
});

// A check under && lets a value through when the other operand is false
// (http://169.254.169.254 here); a return inside a callback does not leave.
router.get('/ssrf/allowlist-and', async (req, res) => {
  const u = new URL(String(req.query.url));
  if (u.protocol === 'https:' && !ALLOWED_HOSTS.has(u.hostname)) return res.status(400).end();
  // ruleid: js-ssrf-taint
  const upstream = await fetch(u);
  res.json({ status: upstream.status });
});

router.get('/ssrf/allowlist-callback-return', async (req, res) => {
  const u = new URL(String(req.query.url));
  if (!ALLOWED_HOSTS.has(u.hostname)) {
    [1].forEach(() => {
      return;
    });
  }
  // ruleid: js-ssrf-taint
  const upstream = await fetch(u);
  res.json({ status: upstream.status });
});

router.get('/ssrf/allowlist-nested-return', async (req, res) => {
  const u = new URL(String(req.query.url));
  if (!ALLOWED_HOSTS.has(u.hostname)) {
    if (req.query.strict) {
      return res.status(400).end();
    }
  }
  // ruleid: js-ssrf-taint
  const upstream = await fetch(u);
  res.json({ status: upstream.status });
});

// Rejected by any operand of || is still rejected; a throw leaves too.
router.get('/ssrf/allowlist-or', async (req, res) => {
  const u = new URL(String(req.query.url));
  if (u.protocol !== 'https:' || !ALLOWED_HOSTS.has(u.hostname)) {
    return res.status(400).end();
  }
  // ok: js-ssrf-taint
  await fetch(u);
  const url = String(req.query.other);
  if (!ALLOWED_HOSTS.has(new URL(url).hostname)) throw new Error('host');
  // ok: js-ssrf-taint
  const upstream = await fetch(url);
  res.json({ status: upstream.status });
});

// A fixed scheme and host, wherever the URL is built.
router.get('/ssrf/fixed-host-variable', async (req, res) => {
  const url = `https://api.github.com/users/${encodeURIComponent(String(req.query.login))}`;
  // ok: js-ssrf-taint
  const user = await fetch(url);
  const endpoint = 'https://api.example.com/search?q=' + req.query.q;
  // ok: js-ssrf-taint
  const search = await axios.get(endpoint);
  const hostOnly = `https://api.example.com${req.query.path}`;
  // ruleid: js-ssrf-taint
  const other = await fetch(hostOnly);
  res.json({ user: user.status, search: search.status, other: other.status });
});

// The host part of the URL is fixed: only its path comes from the request.
router.get('/ssrf/fixed-host', async (req, res) => {
  // ok: js-ssrf-taint
  const user = await fetch(`https://api.github.com/users/${encodeURIComponent(String(req.query.login))}`);
  // ok: js-ssrf-taint
  const repo = await axios.get(`${STATUS_URL}/repos/${req.query.repo}`);
  // ruleid: js-ssrf-taint
  const proxied = await fetch(`https://${req.query.host}/status`);
  res.json({ user: user.status, repo: repo.status, proxied: proxied.status });
});

@Controller('ssrf')
export class SsrfController {
  @Get()
  async preview(@Query('url') url: string) {
    // ruleid: js-ssrf-taint
    const upstream = await axios.get(url, { responseType: 'text' });
    return { status: upstream.status };
  }

  @Get('safe')
  async previewSafe(@Query('url') url: string) {
    const target = new URL(url);
    if (!ALLOWED_HOSTS.has(target.hostname)) {
      throw new BadRequestException('Host not allowed');
    }
    // ok: js-ssrf-taint
    return fetch(target);
  }
}

export async function HEAD(request: NextRequest) {
  const url = request.nextUrl.searchParams.get('url') ?? '';
  // ruleid: js-ssrf-taint
  const upstream = await fetch(url);
  // ok: js-ssrf-taint
  const status = await fetch(STATUS_URL);
  return NextResponse.json({ upstream: upstream.status, status: status.status });
}

// ---------------------------------------------------------------------------
// Path traversal
// ---------------------------------------------------------------------------

router.get('/files/express', async (req, res) => {
  const file = req.query.file;
  // ruleid: js-path-traversal-taint
  const content = await fsp.readFile(path.join(UPLOAD_DIR, file), 'utf8');
  // ruleid: js-path-traversal-taint
  fs.readFileSync(`${UPLOAD_DIR}/${req.params.name}`);
  // ruleid: js-path-traversal-taint
  const stream = fs.createReadStream(path.join(UPLOAD_DIR, req.query.part));
  // ruleid: js-path-traversal-taint
  await fs.promises.readFile(req.query.raw);
  // ok: js-path-traversal-taint
  await fsp.readFile(path.join(UPLOAD_DIR, path.basename(file)), 'utf8');
  // ok: js-path-traversal-taint
  await fsp.readFile(path.join(UPLOAD_DIR, 'terms-of-service.md'), 'utf8');
  stream.pipe(res);
  res.json({ content });
});

router.get('/files/sendfile', (req, res) => {
  // ruleid: js-path-traversal-taint
  res.sendFile(path.join(UPLOAD_DIR, req.query.file));
});

router.get('/files/contained', async (req, res) => {
  const file = req.query.file;
  const filePath = path.resolve(UPLOAD_DIR, file);
  if (!filePath.startsWith(UPLOAD_DIR + path.sep)) {
    return res.status(400).json({ error: 'Invalid file name' });
  }
  // ok: js-path-traversal-taint
  const content = await fsp.readFile(filePath, 'utf8');
  res.json({ content });
});

// With root, Express's send rejects a path that leaves it.
router.get('/files/root/:name', (req, res) => {
  // ok: js-path-traversal-taint
  res.sendFile(req.params.name, { root: PUBLIC_DIR });
});

router.get('/files/download/:name', (req, res) => {
  // ok: js-path-traversal-taint
  res.download(req.params.name, 'report.pdf', { root: PUBLIC_DIR });
});

// Containment by path.relative: the relative path neither climbs out nor is
// absolute (another drive on Windows).
router.get('/files/relative', (req, res) => {
  const p = path.resolve(PUBLIC_DIR, String(req.query.f));
  const rel = path.relative(PUBLIC_DIR, p);
  if (rel.startsWith('..') || path.isAbsolute(rel)) return res.status(400).end();
  // ok: js-path-traversal-taint
  res.send(fs.readFileSync(p, 'utf8'));
});

router.get('/files/no-exit', (req, res) => {
  const p = path.resolve(PUBLIC_DIR, String(req.query.f));
  if (!p.startsWith(PUBLIC_DIR + path.sep)) {
    console.warn('outside');
  }
  // ruleid: js-path-traversal-taint
  res.send(fs.readFileSync(p));
});

router.get('/files/guard-throw', (req, res) => {
  const p = path.resolve(PUBLIC_DIR, String(req.query.f));
  if (!p.startsWith(PUBLIC_DIR + path.sep)) throw new Error('bad');
  // ok: js-path-traversal-taint
  res.send(fs.readFileSync(p));
});

router.get('/files/positive-branch', (req, res) => {
  const p = path.resolve(PUBLIC_DIR, String(req.query.f));
  if (p.startsWith(PUBLIC_DIR + path.sep)) {
    // ok: js-path-traversal-taint
    res.send(fs.readFileSync(p));
  }
  res.end();
});

router.get('/files/relative-unchecked', (req, res) => {
  const p = path.resolve(PUBLIC_DIR, String(req.query.f));
  const rel = path.relative(PUBLIC_DIR, p);
  console.log(rel.startsWith('..'));
  // ruleid: js-path-traversal-taint
  res.send(fs.readFileSync(p, 'utf8'));
});

// Review Focus 5: a prefix check without the separator is not containment.
router.get('/files/prefix-only', async (req, res) => {
  const filePath = path.resolve(UPLOAD_DIR, req.query.file);
  if (!filePath.startsWith(UPLOAD_DIR)) {
    return res.status(400).end();
  }
  // ruleid: js-path-traversal-taint
  const content = await fsp.readFile(filePath, 'utf8');
  res.json({ content });
});

@Controller('files')
export class FilesController {
  @Get()
  async download(@Query('file') file: string) {
    // ruleid: js-path-traversal-taint
    return fsp.readFile(path.join(UPLOAD_DIR, file), 'utf8');
  }

  @Get('safe')
  async downloadSafe(@Query('file') file: string) {
    const filePath = path.resolve(UPLOAD_DIR, file);
    if (!filePath.startsWith(UPLOAD_DIR + path.sep)) {
      throw new BadRequestException('Invalid file name');
    }
    // ok: js-path-traversal-taint
    return fsp.readFile(filePath, 'utf8');
  }
}

export async function OPTIONS(request: NextRequest) {
  const file = request.nextUrl.searchParams.get('file') ?? '';
  // ruleid: js-path-traversal-taint
  const content = await fsp.readFile(path.join(UPLOAD_DIR, file), 'utf8');
  // ok: js-path-traversal-taint
  const named = await fsp.readFile(path.join(UPLOAD_DIR, path.basename(file)), 'utf8');
  return NextResponse.json({ content, named });
}

// ---------------------------------------------------------------------------
// Open redirect
// ---------------------------------------------------------------------------

router.get('/redirect/express', (req, res) => {
  const returnTo = req.query.returnTo || '/';
  if (returnTo === 'header') {
    // ruleid: js-open-redirect-taint
    res.writeHead(302, { Location: returnTo });
    return res.end();
  }
  if (returnTo === 'set') {
    // ruleid: js-open-redirect-taint
    res.setHeader('Location', req.query.next);
    return res.status(302).end();
  }
  // ruleid: js-open-redirect-taint
  res.redirect(returnTo);
});

router.get('/redirect/local', (req, res) => {
  const returnTo = req.query.returnTo || '/';
  const isLocalPath = returnTo.startsWith('/') && !returnTo.startsWith('//') && !returnTo.includes('\\');
  // ok: js-open-redirect-taint
  res.redirect(isLocalPath ? returnTo : '/');
});

router.get('/redirect/guard', (req, res) => {
  const next = String(req.query.next);
  if (!next.startsWith('/') || next.startsWith('//')) {
    return res.redirect('/');
  }
  // ok: js-open-redirect-taint
  res.redirect(next);
});

router.get('/redirect/guard-braceless', (req, res) => {
  const next = String(req.query.next);
  if (!next.startsWith('/') || next.startsWith('//')) return res.redirect('/');
  // ok: js-open-redirect-taint
  res.redirect(next);
});

// Only half the check: https://evil.com does not start with //.
router.get('/redirect/half-guard', (req, res) => {
  const next = String(req.query.next);
  if (next.startsWith('//')) return res.redirect('/');
  // ruleid: js-open-redirect-taint
  res.redirect(next);
});

router.get('/redirect/half-ternary', (req, res) => {
  const next = String(req.query.next);
  const ok = !next.startsWith('//');
  // ruleid: js-open-redirect-taint
  res.redirect(ok ? next : '/');
});

// Both halves, under && with another condition: when strict is unset nothing
// is checked.
router.get('/redirect/guard-and', (req, res) => {
  const next = String(req.query.next);
  if (req.query.strict && (!next.startsWith('/') || next.startsWith('//'))) return res.redirect('/');
  // ruleid: js-open-redirect-taint
  res.redirect(next);
});

router.get('/redirect/guard-reversed', (req, res) => {
  const next = String(req.query.next);
  if (next.startsWith('//') || !next.startsWith('/')) {
    return res.redirect('/');
  }
  // ok: js-open-redirect-taint
  res.redirect(next);
});

router.get('/redirect/ternary-reversed', (req, res) => {
  const next = String(req.query.next);
  const local = !next.startsWith('//') && next.startsWith('/');
  // ok: js-open-redirect-taint
  res.redirect(local ? next : '/');
});

// A same-site path built in a variable first.
router.get('/redirect/settings', (req, res) => {
  const target = `/settings/${req.query.tab}`;
  // ok: js-open-redirect-taint
  res.redirect(target);
});

// A same-site path prefix fixes the target; '/' alone does not ('/' + '/evil.com').
router.get('/redirect/prefix', (req, res) => {
  if (req.query.tab) {
    // ok: js-open-redirect-taint
    return res.redirect(`/settings/${req.query.tab}`);
  }
  // ruleid: js-open-redirect-taint
  res.redirect('/' + req.query.next);
});

router.get('/redirect/constant', (req, res) => {
  // ok: js-open-redirect-taint
  res.redirect(LOGIN_URL);
});

// Helpers whose parameter is the redirect target: only the shape rule sees
// them.
function redirectAfterLogin(res: Response, returnTo: string) {
  // ruleid: js-open-redirect-sink
  res.redirect(returnTo);
}

function redirectWithBase(returnTo: string, baseUrl: string) {
  // ruleid: js-open-redirect-sink
  return NextResponse.redirect(new URL(returnTo, baseUrl));
}

function redirectLocal(res: Response, returnTo: string) {
  if (!returnTo.startsWith('/') || returnTo.startsWith('//')) {
    return res.redirect('/');
  }
  // ok: js-open-redirect-sink
  res.redirect(returnTo);
}

function redirectHalfChecked(res: Response, returnTo: string) {
  if (returnTo.startsWith('//')) {
    return res.redirect('/');
  }
  // ruleid: js-open-redirect-sink
  res.redirect(returnTo);
}

function redirectHome(res: Response, home: string) {
  // ok: js-open-redirect-sink
  res.redirect(LOGIN_URL);
  // ok: js-open-redirect-sink
  res.redirect(`/users/${home}`);
}

@Controller('redirect')
export class RedirectController {
  @Get()
  continueAfterLogin(@Query('returnTo') returnTo: string, @Res() res: Response) {
    const target = returnTo || '/';
    // ruleid: js-open-redirect-taint
    res.redirect(target);
  }

  @Get('safe')
  continueSafe(@Query('returnTo') returnTo: string, @Res() res: Response) {
    const target = returnTo || '/';
    const isLocalPath = target.startsWith('/') && !target.startsWith('//') && !target.includes('\\');
    // ok: js-open-redirect-taint
    res.redirect(isLocalPath ? target : '/');
  }
}

export function POST(request: NextRequest) {
  const returnTo = request.nextUrl.searchParams.get('returnTo') || '/';
  if (returnTo === 'raw') {
    // ruleid: js-open-redirect-taint
    return new Response(null, { status: 302, headers: { Location: returnTo } });
  }
  if (returnTo === 'next') {
    // ruleid: js-open-redirect-taint
    return NextResponse.redirect(returnTo);
  }
  const isLocalPath = returnTo.startsWith('/') && !returnTo.startsWith('//') && !returnTo.includes('\\');
  if (returnTo === 'local') {
    // ok: js-open-redirect-taint
    return NextResponse.redirect(new URL(isLocalPath ? returnTo : '/', request.url));
  }
  // ruleid: js-open-redirect-taint
  return NextResponse.redirect(new URL(returnTo, request.url));
}

export function PATCH(request: NextRequest) {
  const tab = request.nextUrl.searchParams.get('tab');
  const dest = `/settings/${tab}`;
  // ok: js-open-redirect-taint
  return NextResponse.redirect(new URL(dest, request.url));
}

export function DELETE() {
  // ok: js-open-redirect-taint
  return NextResponse.redirect(LOGIN_URL);
}

export { router, renderResults, renderPage, renderSafe, redirectAfterLogin, redirectWithBase, redirectLocal, redirectHalfChecked, redirectHome };
