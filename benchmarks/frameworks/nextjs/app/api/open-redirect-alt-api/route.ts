import { NextRequest } from 'next/server';

export function GET(request: NextRequest) {
  const returnTo = request.nextUrl.searchParams.get('returnTo') || '/';
  return new Response(null, { status: 302, headers: { Location: returnTo } }); // EVAL-SINK
}
