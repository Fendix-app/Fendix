import * as jwt from 'jsonwebtoken';
import { NextRequest, NextResponse } from 'next/server';

function getClaims(token: string) {
  return jwt.decode(token) as jwt.JwtPayload | null; // EVAL-SINK
}

export function GET(request: NextRequest) {
  const token = (request.headers.get('authorization') || '').replace(/^Bearer /, '');
  const claims = getClaims(token);
  if (!claims || claims.role !== 'admin') {
    return NextResponse.json({ error: 'Forbidden' }, { status: 403 });
  }
  return NextResponse.json({ user: claims.sub, permissions: ['reports:read', 'users:write'] });
}
