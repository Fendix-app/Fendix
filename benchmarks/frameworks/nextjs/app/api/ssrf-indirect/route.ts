import { NextRequest, NextResponse } from 'next/server';

async function fetchPreview(url: string) {
  const upstream = await fetch(url); // EVAL-SINK
  return { status: upstream.status, body: await upstream.text() };
}

export async function GET(request: NextRequest) {
  const url = request.nextUrl.searchParams.get('url') ?? '';
  const preview = await fetchPreview(url);
  return NextResponse.json(preview);
}
