import { NextRequest, NextResponse } from 'next/server';

const ALLOWED_HOSTS = new Set(['api.github.com', 'cdn.example.com']);

export async function GET(request: NextRequest) {
  const url = request.nextUrl.searchParams.get('url') ?? '';
  let target: URL;
  try {
    target = new URL(url);
  } catch {
    return NextResponse.json({ error: 'Invalid URL' }, { status: 400 });
  }
  if (target.protocol !== 'https:' || !ALLOWED_HOSTS.has(target.hostname)) {
    return NextResponse.json({ error: 'Host not allowed' }, { status: 400 });
  }
  const upstream = await fetch(target); // EVAL-SAFE
  return NextResponse.json({ status: upstream.status, body: await upstream.text() });
}
