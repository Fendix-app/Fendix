import { NextRequest, NextResponse } from 'next/server';

export function GET(request: NextRequest) {
  const returnTo = request.nextUrl.searchParams.get('returnTo') || '/';
  return NextResponse.redirect(new URL(returnTo, request.url)); // EVAL-SINK
}
