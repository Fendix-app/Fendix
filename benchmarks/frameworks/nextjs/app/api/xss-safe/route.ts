import escapeHtml from 'escape-html';
import { NextRequest } from 'next/server';

export function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams.get('q') ?? '';
  return new Response(`<h1>Search results for ${escapeHtml(q)}</h1>`, { headers: { 'Content-Type': 'text/html; charset=utf-8' } }); // EVAL-SAFE
}
