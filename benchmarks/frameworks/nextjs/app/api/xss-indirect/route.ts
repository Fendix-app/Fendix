import { NextRequest } from 'next/server';

function renderResults(q: string): Response {
  return new Response(`<h1>Search results for ${q}</h1>`, { headers: { 'Content-Type': 'text/html; charset=utf-8' } }); // EVAL-SINK
}

export function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams.get('q') ?? '';
  return renderResults(q);
}
