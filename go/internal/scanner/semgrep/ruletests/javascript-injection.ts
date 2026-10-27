// Rule tests for rules/javascript-injection.yaml: SQL injection, command
// injection and server-side template injection, in the Express, NestJS and
// Next.js idioms. See README.md for the annotation format.

import { BadRequestException, Body, Controller, Get, Headers, Param, Post, Query, Req } from '@nestjs/common';
import { Prisma, PrismaClient } from '@prisma/client';
import * as ejs from 'ejs';
import express from 'express';
import Handlebars from 'handlebars';
import { NextRequest, NextResponse } from 'next/server';
import { exec, execFile, execSync, spawn } from 'node:child_process';
import * as fs from 'node:fs';
import { promisify } from 'node:util';
import nunjucks from 'nunjucks';
import { Pool } from 'pg';
import postgres from 'postgres';
import pug from 'pug';
import { sql as slonikSql } from 'slonik';
import SQL from 'sql-template-strings';

const pool = new Pool();
const prisma = new PrismaClient();
const sql = postgres();
const execAsync = promisify(exec);
const execFileAsync = promisify(execFile);
const router = express.Router();
const db: any = {};
const apollo: any = {};
const GET_USER = 'query GetUser($id: ID!) { user(id: $id) { name } }';
declare function loadColumns(): Record<string, string>;
declare function buildSql(s: TemplateStringsArray, ...v: unknown[]): string;
declare function mysqlEscapeTemplate(s: TemplateStringsArray, ...v: unknown[]): string;
declare function sqlConcat(s: TemplateStringsArray, ...v: unknown[]): string;
declare function rawSql(s: TemplateStringsArray, ...v: unknown[]): string;
declare function toSqlString(s: TemplateStringsArray, ...v: unknown[]): string;

const DEFAULT_ROLE = 'member';
const SORT_MAP = { name: 'name', created: 'created_at' };
const ALLOWED_SORT = new Set(['name', 'created_at']);
const COLUMNS = loadColumns();

// Helpers whose every return is a literal or a lookup in a literal map.
function sortColumn(s: string) {
  return SORT_MAP[s] ?? 'id';
}

function sortColumnSwitch(s: string) {
  switch (s) {
    case 'name':
      return 'name';
    case 'created':
      return 'created_at';
    default:
      return 'id';
  }
}

// Helpers that can hand the input back.
function echoColumn(s: string) {
  return s.trim();
}

function pickColumn(s: string) {
  if (s === 'name') {
    return 'name';
  }
  return s;
}
const LOG_DIR = '/var/log/app';
const FOOTER_TEMPLATE = '<footer><%= year %></footer>';

// ---------------------------------------------------------------------------
// SQL injection
// ---------------------------------------------------------------------------

router.get('/sqli/express', async (req, res) => {
  const name = req.query.name;
  // ruleid: js-sqli-taint, js-sqli-sink
  const result = await pool.query(`SELECT id FROM users WHERE name = '${name}'`);
  // ruleid: js-sqli-taint, js-sqli-sink
  await pool.query("SELECT id FROM users WHERE name = '" + req.body.name + "'");
  const byId = 'SELECT id FROM users WHERE id = ' + req.params.id;
  // ruleid: js-sqli-taint
  await pool.query(byId);
  // ok: js-sqli-taint, js-sqli-sink
  await pool.query('SELECT id FROM users WHERE name = $1', [name]);
  // ok: js-sqli-taint, js-sqli-sink
  await pool.query({ text: 'SELECT id FROM users WHERE name = $1', values: [name] });
  res.json(result.rows);
});

// Review Focus 1: a tagged template is parameterized, never SQL injection.
router.get('/sqli/tagged', async (req, res) => {
  const id = req.query.id;
  // ok: js-sqli-taint, js-sqli-sink
  const users = await sql`SELECT * FROM users WHERE id = ${id}`;
  // ok: js-sqli-taint, js-sqli-sink
  const rows = await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`;
  // ok: js-sqli-taint, js-sqli-sink
  await prisma.$queryRaw(Prisma.sql`SELECT * FROM users WHERE id = ${id}`);
  const query = Prisma.sql`SELECT * FROM users WHERE id = ${id}`;
  // ok: js-sqli-taint, js-sqli-sink
  await prisma.$queryRaw(query);
  res.json({ users, rows });
});

// Review Focus 1 needs the tag to be named sql. A project's own tag may just
// concatenate, so buildSql, rawSql, sqlConcat, toSqlString and
// mysqlEscapeTemplate stay sinks, as do String.raw and drizzle's sql.raw(...).
// slonik's typed tags and drizzle's sql are in javascript-injection.slonik.ts
// and javascript-injection.drizzle.ts, where they are imported as sql.
router.get('/sqli/tag-names', async (req, res) => {
  const id = req.params.id;
  // ok: js-sqli-taint, js-sqli-sink
  await pool.query(SQL`SELECT * FROM users WHERE id = ${id}`);
  // ruleid: js-sqli-taint
  await pool.query(buildSql`SELECT * FROM users WHERE id = ${id}`);
  // ruleid: js-sqli-taint
  await pool.query(mysqlEscapeTemplate`SELECT * FROM users WHERE id = ${id}`);
  // ruleid: js-sqli-taint
  await pool.query(sqlConcat`SELECT * FROM users WHERE id = ${id}`);
  // ruleid: js-sqli-taint
  await pool.query(rawSql`SELECT * FROM users WHERE id = ${id}`);
  // ruleid: js-sqli-taint
  await pool.query(toSqlString`SELECT * FROM users WHERE id = ${id}`);
  // ruleid: js-sqli-taint
  await pool.query(String.raw`SELECT * FROM users WHERE id = ${id}`);
  // An aliased import is not recognised: only the local name is seen.
  // ruleid: js-sqli-taint
  await pool.query(slonikSql`SELECT * FROM users WHERE id = ${id}`);
  res.end();
});

// A query object built first and passed by name is pg's parameterized form;
// a GraphQL client's options object is not SQL at all. The text field of a
// config object is still the query text.
router.get('/sqli/config-variable', async (req, res) => {
  const query = { text: 'SELECT * FROM users WHERE id = $1', values: [req.params.id] };
  // ok: js-sqli-taint, js-sqli-sink
  const r = await pool.query(query);
  const options = { query: GET_USER, variables: { id: req.params.id } };
  // ok: js-sqli-taint, js-sqli-sink
  await apollo.query(options);
  // ruleid: js-sqli-taint
  await pool.query({ text: 'SELECT * FROM users WHERE id = ' + req.params.id });
  // The text of a config object bound to a name is still the query text; the
  // finding is on the text.
  // ruleid: js-sqli-taint
  const byName = { text: 'SELECT * FROM users WHERE id = ' + req.params.id };
  await pool.query(byName);
  res.json(r.rows);
});

// An identifier made of constants is not input: a literal-map lookup with a
// literal fallback, a helper that returns only those, and IN-list
// placeholders built from the list's length or index. The shape rule still
// warns: it sees a non-constant value in the query text.
router.post('/sqli/constant-identifiers', async (req, res) => {
  const ids = req.body.ids;
  const col = sortColumn(req.query.sort);
  // ok: js-sqli-taint
  // ruleid: js-sqli-sink
  await pool.query('SELECT * FROM t ORDER BY ' + col);
  const col2 = sortColumnSwitch(req.query.sort);
  // ok: js-sqli-taint
  // ruleid: js-sqli-sink
  await pool.query('SELECT * FROM t ORDER BY ' + col2);
  const col3 = SORT_MAP[req.query.sort] ?? 'id';
  // ok: js-sqli-taint
  // ruleid: js-sqli-sink
  await pool.query(`SELECT * FROM t ORDER BY ${col3}`);
  const marks = ids.map(() => '?').join(',');
  // ok: js-sqli-taint
  // ruleid: js-sqli-sink
  await pool.query('SELECT * FROM t WHERE id IN (' + marks + ')', ids);
  const repeated = '?,'.repeat(ids.length).slice(0, -1);
  // ok: js-sqli-taint
  // ruleid: js-sqli-sink
  await pool.query(`SELECT * FROM t WHERE id IN (${repeated})`, ids);
  const numbered = ids.map((_: unknown, i: number) => '$' + (i + 1)).join(', ');
  // ok: js-sqli-taint
  // ruleid: js-sqli-sink
  await pool.query('SELECT * FROM t WHERE id IN (' + numbered + ')', ids);
  res.end();
});

// The same shapes with the input still in them.
router.post('/sqli/identifier-controls', async (req, res) => {
  const ids = req.body.ids;
  // ruleid: js-sqli-taint, js-sqli-sink
  await pool.query('SELECT * FROM t ORDER BY ' + req.query.sort);
  // ruleid: js-sqli-taint, js-sqli-sink
  await pool.query('SELECT * FROM t WHERE id IN (' + ids.join(',') + ')');
  // ruleid: js-sqli-taint, js-sqli-sink
  await pool.query('SELECT * FROM t ORDER BY ' + echoColumn(req.query.sort));
  // ruleid: js-sqli-taint, js-sqli-sink
  await pool.query('SELECT * FROM t ORDER BY ' + pickColumn(req.query.sort));
  // ruleid: js-sqli-taint, js-sqli-sink
  await pool.query(`SELECT * FROM t ORDER BY ${COLUMNS[req.query.sort] ?? 'id'}`);
  // ruleid: js-sqli-taint, js-sqli-sink
  await pool.query(`SELECT * FROM t ORDER BY ${SORT_MAP[req.query.sort] ?? req.query.sort}`);
  const echoed = ids.map((id: string) => id).join(',');
  // ruleid: js-sqli-taint, js-sqli-sink
  await pool.query('SELECT * FROM t WHERE id IN (' + echoed + ')');
  res.end();
});

// An identifier allowlist that rejects (return or throw), resets the value to
// a literal, or picks a literal in a ternary.
router.get('/sqli/allowlist', async (req, res) => {
  const sort = req.query.sort;
  if (!ALLOWED_SORT.has(sort)) return res.status(400).end();
  // ok: js-sqli-taint
  // ruleid: js-sqli-sink
  await pool.query('SELECT * FROM t ORDER BY ' + sort);
  let dir = req.query.dir;
  if (!['asc', 'desc'].includes(dir)) dir = 'asc';
  // ok: js-sqli-taint
  // ruleid: js-sqli-sink
  await pool.query(`SELECT * FROM t ORDER BY name ${dir}`);
  const dir2 = ['asc', 'desc'].includes(req.query.dir2) ? req.query.dir2 : 'asc';
  // ok: js-sqli-taint
  // ruleid: js-sqli-sink
  await pool.query(`SELECT * FROM t ORDER BY name ${dir2}`);
  const { order } = req.query;
  if (!ALLOWED_SORT.has(order)) throw new Error('bad sort');
  // ok: js-sqli-taint
  // ruleid: js-sqli-sink
  await pool.query(`SELECT * FROM t ORDER BY ${order}`);
  res.end();
});

// The same checks that do not hold.
router.get('/sqli/allowlist-controls', async (req, res) => {
  const sort = req.query.sort;
  if (req.query.strict && !ALLOWED_SORT.has(sort)) return res.status(400).end();
  // ruleid: js-sqli-taint, js-sqli-sink
  await pool.query('SELECT * FROM t ORDER BY ' + sort);
  const sort2 = req.query.sort2;
  if (!ALLOWED_SORT.has(sort2)) console.warn('unknown sort');
  // ruleid: js-sqli-taint, js-sqli-sink
  await pool.query('SELECT * FROM t ORDER BY ' + sort2);
  let dir = req.query.dir;
  if (!['asc', 'desc'].includes(dir)) dir = req.query.fallback;
  // ruleid: js-sqli-taint, js-sqli-sink
  await pool.query(`SELECT * FROM t ORDER BY name ${dir}`);
  const dir2 = ['asc', 'desc'].includes(req.query.dir2) ? req.query.dir2 : req.query.other;
  // ruleid: js-sqli-taint, js-sqli-sink
  await pool.query(`SELECT * FROM t ORDER BY name ${dir2}`);
  res.end();
});

router.get('/sqli/prisma-unsafe', async (req, res) => {
  // ruleid: js-sqli-taint, js-sqli-sink
  const rows = await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE email = '${req.query.email}'`);
  res.json(rows);
});

// A module constant is not input.
router.get('/sqli/constant', async (req, res) => {
  // ok: js-sqli-taint, js-sqli-sink
  const result = await pool.query(`SELECT id FROM users WHERE role = '${DEFAULT_ROLE}'`);
  res.json(result.rows);
});

// The helper is reached through a call; only the shape rule sees it.
async function findUsersByName(name: string) {
  // ruleid: js-sqli-sink
  const result = await pool.query(`SELECT id FROM users WHERE name = '${name}'`);
  return result.rows;
}

@Controller('sqli')
export class SqliController {
  @Get('sorted')
  async sorted(@Query('sort') sort: string) {
    if (!ALLOWED_SORT.has(sort)) throw new BadRequestException();
    // ok: js-sqli-taint
    // ruleid: js-sqli-sink
    return pool.query(`SELECT * FROM items ORDER BY ${sort}`);
  }

  @Get('many')
  async many(@Query('ids') ids: string[]) {
    const ph = ids.map(() => '?').join(',');
    // ok: js-sqli-taint
    // ruleid: js-sqli-sink
    return pool.query(`SELECT * FROM items WHERE id IN (${ph})`, ids);
  }

  @Get()
  async search(@Query('name') name: string) {
    // ruleid: js-sqli-taint, js-sqli-sink
    const result = await pool.query(`SELECT id FROM users WHERE name = '${name}'`);
    return result.rows;
  }

  @Get('safe')
  async searchSafe(@Query('name') name: string) {
    // ok: js-sqli-taint, js-sqli-sink
    const result = await pool.query('SELECT id FROM users WHERE name = $1', [name]);
    return result.rows;
  }

  @Get('raw/:id')
  async byId(@Req() request: express.Request) {
    // ruleid: js-sqli-taint, js-sqli-sink
    return pool.query('SELECT id FROM users WHERE id = ' + request.params.id);
  }
}

export async function GET(request: NextRequest) {
  const name = request.nextUrl.searchParams.get('name') ?? '';
  // ruleid: js-sqli-taint, js-sqli-sink
  const result = await pool.query(`SELECT id FROM users WHERE name = '${name}'`);
  // ok: js-sqli-taint, js-sqli-sink
  const safe = await pool.query('SELECT id FROM users WHERE name = $1', [name]);
  return NextResponse.json({ result, safe });
}

// ---------------------------------------------------------------------------
// Command injection
// ---------------------------------------------------------------------------

router.post('/cmdi/express', async (req, res) => {
  const host = req.body.host;
  // ruleid: js-cmdi-taint, js-cmdi-sink
  const { stdout } = await execAsync(`ping -c 1 ${host}`);
  // ruleid: js-cmdi-taint, js-cmdi-sink
  execSync(`nslookup ${host}`, { encoding: 'utf8' });
  // ruleid: js-cmdi-taint, js-cmdi-sink
  exec('dig ' + host, () => undefined);
  // ruleid: js-cmdi-taint
  spawn(`traceroute ${host}`, { shell: true });
  // ok: js-cmdi-taint, js-cmdi-sink
  await execFileAsync('ping', ['-c', '1', host]);
  // ok: js-cmdi-taint, js-cmdi-sink
  spawn('ping', ['-c', '1', host]);
  // ok: js-cmdi-taint, js-cmdi-sink
  const match = /^[a-z.]+$/.exec(host);
  res.json({ stdout, match });
});

router.get('/cmdi/constant', async (req, res) => {
  // ok: js-cmdi-taint, js-cmdi-sink
  const { stdout } = await execAsync(`du -sh ${LOG_DIR}`);
  res.json({ usage: stdout });
});

async function pingHost(host: string) {
  // ruleid: js-cmdi-sink
  const { stdout } = await execAsync(`ping -c 1 ${host}`);
  return stdout;
}

@Controller('cmdi')
export class CmdiController {
  @Post()
  ping(@Body('host') host: string) {
    // ruleid: js-cmdi-taint, js-cmdi-sink
    return execSync(`ping -c 1 ${host}`, { encoding: 'utf8' });
  }

  @Post('safe')
  async pingSafe(@Body('host') host: string) {
    // ok: js-cmdi-taint, js-cmdi-sink
    return execFileAsync('ping', ['-c', '1', host]);
  }
}

export async function POST(request: NextRequest) {
  const { host } = (await request.json()) as { host: string };
  // ruleid: js-cmdi-taint, js-cmdi-sink
  const { stdout } = await execAsync(`ping -c 1 ${host}`);
  // ok: js-cmdi-taint, js-cmdi-sink
  const safe = await execFileAsync('ping', ['-c', '1', host]);
  return NextResponse.json({ stdout, safe });
}

// ---------------------------------------------------------------------------
// Server-side template injection
// ---------------------------------------------------------------------------

router.post('/ssti/express', (req, res) => {
  const template = req.body.template;
  // ruleid: js-ssti-taint
  const html = ejs.render(template, { year: 2026 });
  // ruleid: js-ssti-taint
  const fn = pug.compile(req.body.layout);
  // ruleid: js-ssti-taint
  Handlebars.compile(req.query.view);
  // ruleid: js-ssti-taint
  nunjucks.renderString(req.body.page, {});
  // ok: js-ssti-taint
  const footer = ejs.render(FOOTER_TEMPLATE, { name: req.body.name });
  res.json({ html, fn, footer });
});

// A helper whose parameter is the template: only the shape rule sees it.
function renderPreview(template: string) {
  // ruleid: js-ssti-sink
  return ejs.render(template, { year: 2026 });
}

// ok: js-ssti-sink
const compileView = (source: string) => Handlebars.compile(FOOTER_TEMPLATE)({ source });

function renderEmail(name: string) {
  const template = fs.readFileSync('templates/email.ejs', 'utf8');
  // ok: js-ssti-taint, js-ssti-sink
  return ejs.render(template, { name });
}

function renderFooter(year: number) {
  // ok: js-ssti-taint, js-ssti-sink
  return ejs.render(FOOTER_TEMPLATE, { year });
}

@Controller('ssti')
export class SstiController {
  @Post()
  preview(@Body('template') template: string) {
    // ruleid: js-ssti-taint, js-ssti-sink
    return ejs.render(template, { year: 2026 });
  }

  @Post('safe')
  previewSafe(@Body('customer') customer: string) {
    // ok: js-ssti-taint
    return ejs.render(FOOTER_TEMPLATE, { customer });
  }
}

export async function PUT(request: NextRequest, context: { params: Promise<{ view: string }> }) {
  const { template } = (await request.json()) as { template: string };
  // ruleid: js-ssti-taint
  const html = ejs.render(template, { year: 2026 });
  const { view } = await context.params;
  // ruleid: js-ssti-taint
  const page = pug.render(view);
  // ok: js-ssti-taint
  const footer = ejs.render(FOOTER_TEMPLATE, { year: 2026 });
  return NextResponse.json({ html, page, footer });
}

export { router, sortColumn, sortColumnSwitch, echoColumn, pickColumn, findUsersByName, pingHost, renderPreview, compileView, renderEmail, renderFooter };
