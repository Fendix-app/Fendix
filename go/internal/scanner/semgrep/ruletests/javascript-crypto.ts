// Rule tests for rules/javascript-crypto.yaml: weak password hashing, JWTs
// trusted without signature verification, and tokens from a non-cryptographic
// RNG, in the Express, NestJS and Next.js idioms. See README.md for the
// annotation format.

import { Body, Controller, ForbiddenException, Get, Headers, Post } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import express from 'express';
import * as jwt from 'jsonwebtoken';
import { NextRequest, NextResponse } from 'next/server';
import * as crypto from 'node:crypto';

const router = express.Router();

const JWT_SECRET = process.env.JWT_SECRET ?? '';
const PUBLIC_KEYS = new Map<string, string | undefined>([['auth-2026-01', process.env.JWT_PUBLIC_KEY]]);
const FEATURED = ['getting-started', 'billing', 'api-keys'];

// ---------------------------------------------------------------------------
// Weak password hashing
// ---------------------------------------------------------------------------

router.post('/register', async (req, res) => {
  const { email, password } = req.body;
  // ruleid: js-weak-password-hash-taint, js-weak-password-hash-sink
  const passwordHash = crypto.createHash('md5').update(password).digest('hex');
  // ruleid: js-weak-password-hash-taint, js-weak-password-hash-sink
  crypto.createHash('sha1').update(req.body.newPassword).digest('hex');
  const pw = req.body.password;
  // ruleid: js-weak-password-hash-taint
  crypto.createHash('SHA1').update(pw).digest('base64');
  // ok: js-weak-password-hash-taint, js-weak-password-hash-sink
  const strong = await bcrypt.hash(password, 12);
  // ok: js-weak-password-hash-taint, js-weak-password-hash-sink
  crypto.createHash('sha256').update(password).digest('hex');
  // ok: js-weak-password-hash-taint, js-weak-password-hash-sink
  const etag = crypto.createHash('md5').update(JSON.stringify(req.body.items)).digest('hex');
  res.status(201).json({ email, passwordHash, strong, etag });
});

// The brief's name test, pass(word)?|pwd: a short or prefixed name counts too.
function hashShortNames(pass: string, userPass: string, passwd: string) {
  // ruleid: js-weak-password-hash-sink
  const a = crypto.createHash('md5').update(pass).digest('hex');
  // ruleid: js-weak-password-hash-sink
  const b = crypto.createHash('sha1').update(userPass).digest('hex');
  // ruleid: js-weak-password-hash-sink
  const c = crypto.createHash('md5').update(passwd).digest('hex');
  return [a, b, c];
}

// Reached through a call: only the shape rule sees it.
function hashPassword(password: string) {
  // ruleid: js-weak-password-hash-sink
  return crypto.createHash('md5').update(password).digest('hex');
}

// ok: js-weak-password-hash-sink
const DIGEST = crypto.createHash('md5').update('static-build-input').digest('hex');

@Controller('register')
export class RegisterController {
  @Post()
  register(@Body('email') email: string, @Body('password') password: string) {
    // ruleid: js-weak-password-hash-taint, js-weak-password-hash-sink
    const passwordHash = crypto.createHash('md5').update(password).digest('hex');
    return { email, passwordHash };
  }

  @Post('safe')
  async registerSafe(@Body('password') password: string) {
    // ok: js-weak-password-hash-taint, js-weak-password-hash-sink
    return bcrypt.hash(password, 12);
  }
}

export async function POST(request: NextRequest) {
  const { email, password } = (await request.json()) as { email: string; password: string };
  // ruleid: js-weak-password-hash-taint, js-weak-password-hash-sink
  const passwordHash = crypto.createHash('md5').update(password).digest('hex');
  // ok: js-weak-password-hash-taint, js-weak-password-hash-sink
  const strong = await bcrypt.hash(password, 12);
  return NextResponse.json({ email, passwordHash, strong });
}

// ---------------------------------------------------------------------------
// JWT accepted without signature verification
// ---------------------------------------------------------------------------

router.get('/admin', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  // ruleid: js-jwt-no-verify-taint
  const claims = jwt.decode(token);
  if (!claims || claims.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json({ user: claims.sub });
});

router.get('/admin/verified', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  let claims;
  try {
    // ok: js-jwt-no-verify-taint, js-jwt-no-verify-sink
    claims = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] });
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
  res.json({ claims });
});

// Reading only the unverified header to pick a key, then verifying, is fine.
router.get('/admin/kid', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  // ok: js-jwt-no-verify-taint, js-jwt-no-verify-sink
  const decoded = jwt.decode(token, { complete: true });
  const publicKey = decoded && PUBLIC_KEYS.get(decoded.header.kid);
  if (!publicKey) {
    return res.status(401).json({ error: 'Unknown signing key' });
  }
  const claims = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
  res.json({ claims });
});

router.get('/admin/challenge', (req, res) => {
  const token = String(req.headers.authorization);
  // ok: js-jwt-no-verify-taint
  const decoded = token.includes('.') ? jwt.decode(token) : null;
  jwt.verify(token, JWT_SECRET, (err: unknown) => {
    res.json({ ok: !err && decoded !== null });
  });
});

// Decoding a cookie token only to log its key id reads no claim.
router.get('/admin/log-kid', (req, res) => {
  // ok: js-jwt-no-verify-taint
  const d = jwt.decode(req.cookies.t, { complete: true });
  console.log(d?.header.kid);
  res.end();
});

// complete: true does not help when the payload is what gets trusted.
router.get('/admin/payload', (req, res) => {
  const token = String(req.headers.authorization);
  // ruleid: js-jwt-no-verify-taint
  const decoded = jwt.decode(token, { complete: true });
  if (decoded && decoded.payload.role === 'admin') {
    return res.json({ admin: true });
  }
  res.status(403).end();
});

function getClaims(token: string) {
  // ruleid: js-jwt-no-verify-sink
  return jwt.decode(token) as jwt.JwtPayload | null;
}

// Decoded to read a claim and verified before anything is trusted.
function checkIssuer(token: string, key: string) {
  // ok: js-jwt-no-verify-sink
  const decoded = token.length > 0 ? jwt.decode(token) : null;
  jwt.verify(token, key, (err: unknown) => {
    if (!err && decoded) {
      console.log('verified');
    }
  });
}

// A token the server issued and holds itself, not one handed in.
function lastLoginOf(sessions: Map<string, string>, userId: string) {
  const issued = sessions.get(userId) ?? '';
  // ok: js-jwt-no-verify-taint, js-jwt-no-verify-sink
  const parsed = jwt.decode(issued, { json: true });
  return parsed?.iat;
}

@Controller('admin')
export class AdminController {
  @Get()
  adminSummary(@Headers('authorization') authorization: string) {
    const token = (authorization || '').replace(/^Bearer /, '');
    // ruleid: js-jwt-no-verify-taint
    const claims = jwt.decode(token) as jwt.JwtPayload | null;
    if (!claims || claims.role !== 'admin') {
      throw new ForbiddenException();
    }
    return { user: claims.sub };
  }

  @Get('verified')
  verified(@Headers('authorization') authorization: string) {
    // ok: js-jwt-no-verify-taint, js-jwt-no-verify-sink
    return jwt.verify(authorization, JWT_SECRET, { algorithms: ['HS256'] });
  }
}

export function GET(request: NextRequest) {
  const token = (request.headers.get('authorization') || '').replace(/^Bearer /, '');
  if (token === 'kid') {
    // ok: js-jwt-no-verify-taint, js-jwt-no-verify-sink
    const decoded = jwt.decode(token, { complete: true });
    const publicKey = decoded?.header.kid ? PUBLIC_KEYS.get(decoded.header.kid) : undefined;
    return NextResponse.json(jwt.verify(token, publicKey ?? '', { algorithms: ['RS256'] }));
  }
  // ruleid: js-jwt-no-verify-taint
  const claims = jwt.decode(token) as jwt.JwtPayload | null;
  if (!claims || claims.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }
  return NextResponse.json({ user: claims.sub });
}

// ---------------------------------------------------------------------------
// Tokens from a non-cryptographic RNG
// ---------------------------------------------------------------------------

router.post('/reset', (req, res) => {
  // ruleid: js-weak-random-token-taint
  const resetToken = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  const user = { email: req.body.email, sessionId: '' };
  // ruleid: js-weak-random-token-taint
  user.sessionId = String(Math.random());
  // ruleid: js-weak-random-token-taint
  res.json({ apiKey: Math.random().toString(16).slice(2), resetToken });
});

function generateResetToken() {
  // ruleid: js-weak-random-token-taint
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
}

// Timing jitter is not a token, even when its name starts with one of the
// words: the word must be the name's last segment (optionally + Id, Value...).
function scheduleRetry() {
  // ok: js-weak-random-token-taint
  const resetDelayMs = Math.floor(Math.random() * 1000);
  // ok: js-weak-random-token-taint
  const cfg = { sessionTimeout: 1000 + Math.random() * 500 };
  // ok: js-weak-random-token-taint
  const tokenRefreshJitter = Math.random() * 30000;
  // ruleid: js-weak-random-token-taint
  const csrfToken = Math.random().toString(36);
  // ruleid: js-weak-random-token-taint
  const otp = Math.floor(100000 + Math.random() * 900000);
  // ruleid: js-weak-random-token-taint
  const API_KEY = Math.random().toString(16);
  // ruleid: js-weak-random-token-taint
  const reset_token_value = String(Math.random());
  return { resetDelayMs, cfg, tokenRefreshJitter, csrfToken, otp, API_KEY, reset_token_value };
}

router.get('/featured', (req, res) => {
  // ok: js-weak-random-token-taint
  const picks = [...FEATURED].sort(() => Math.random() - 0.5).slice(0, 3);
  // ok: js-weak-random-token-taint
  const resetToken = crypto.randomBytes(32).toString('hex');
  // ok: js-weak-random-token-taint
  const retryDelayMs = Math.floor(Math.random() * 1000);
  // ok: js-weak-random-token-taint
  const footprint = Math.random();
  res.json({ picks, resetToken, retryDelayMs, footprint });
});

@Controller('reset')
export class ResetController {
  @Post()
  requestReset(@Body('email') email: string) {
    // ruleid: js-weak-random-token-taint
    const resetToken = Math.random().toString(36).slice(2);
    // ok: js-weak-random-token-taint
    const csrfToken = crypto.randomUUID();
    return { email, resetToken, csrfToken };
  }
}

export async function PUT(request: NextRequest) {
  const { email } = (await request.json()) as { email: string };
  // ruleid: js-weak-random-token-taint
  const resetToken = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2);
  // ok: js-weak-random-token-taint
  const picks = [...FEATURED].sort(() => Math.random() - 0.5);
  return NextResponse.json({ email, resetToken, picks });
}

export { router, hashShortNames, scheduleRetry, hashPassword, getClaims, checkIssuer, lastLoginOf, generateResetToken, DIGEST };
