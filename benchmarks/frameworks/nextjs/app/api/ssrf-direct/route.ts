import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  const url = request.nextUrl.searchParams.get('url') ?? '';
  const upstream = await fetch(url); // EVAL-SINK
  return NextResponse.json({ status: upstream.status, body: await upstream.text() });
}
