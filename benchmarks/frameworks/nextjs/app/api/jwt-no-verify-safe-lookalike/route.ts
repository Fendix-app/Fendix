import * as jwt from 'jsonwebtoken';
import { NextRequest, NextResponse } from 'next/server';

const PUBLIC_KEYS = new Map<string, string | undefined>([
  ['auth-2026-01', process.env.JWT_PUBLIC_KEY_CURRENT],
  ['auth-2025-07', process.env.JWT_PUBLIC_KEY_PREVIOUS],
]);

export function GET(request: NextRequest) {
  const token = (request.headers.get('authorization') || '').replace(/^Bearer /, '');
  const decoded = jwt.decode(token, { complete: true }); // EVAL-SAFE
  const publicKey = decoded?.header.kid ? PUBLIC_KEYS.get(decoded.header.kid) : undefined;
  if (!publicKey) {
    return NextResponse.json({ error: 'Unknown signing key' }, { status: 401 });
  }
  let claims: jwt.JwtPayload;
  try {
    claims = jwt.verify(token, publicKey, { algorithms: ['RS256'] }) as jwt.JwtPayload;
  } catch {
    return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
  }
  if (claims.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }
  return NextResponse.json({ user: claims.sub, permissions: ['reports:read', 'users:write'] });
}
