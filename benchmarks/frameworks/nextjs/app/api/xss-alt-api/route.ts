import { NextRequest, NextResponse } from 'next/server';

export function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams.get('q') ?? '';
  return new NextResponse(`<h1>Search results for ${q}</h1>`, { headers: { 'Content-Type': 'text/html; charset=utf-8' } }); // EVAL-SINK
}
