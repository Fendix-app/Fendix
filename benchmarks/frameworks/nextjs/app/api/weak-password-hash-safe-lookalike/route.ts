import { NextResponse } from 'next/server';
import * as crypto from 'node:crypto';

const PLANS = [
  { id: 'free', priceCents: 0 },
  { id: 'team', priceCents: 2000 },
  { id: 'enterprise', priceCents: 9900 },
];

export function GET() {
  const body = JSON.stringify(PLANS);
  const etag = crypto.createHash('md5').update(body).digest('hex'); // EVAL-SAFE
  return new NextResponse(body, { headers: { 'Content-Type': 'application/json', ETag: `"${etag}"` } });
}
