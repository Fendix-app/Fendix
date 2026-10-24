import * as jwt from 'jsonwebtoken';
import { NextRequest, NextResponse } from 'next/server';

const JWT_SECRET = process.env.JWT_SECRET ?? '';

export function GET(request: NextRequest) {
  const token = (request.headers.get('authorization') || '').replace(/^Bearer /, '');
  let claims: jwt.JwtPayload;
  try {
    claims = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }) as jwt.JwtPayload; // EVAL-SAFE
  } catch {
    return NextResponse.json({ error: 'Invalid token' }, { status: 401 });
  }
  if (claims.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }
  return NextResponse.json({ user: claims.sub, permissions: ['reports:read', 'users:write'] });
}
