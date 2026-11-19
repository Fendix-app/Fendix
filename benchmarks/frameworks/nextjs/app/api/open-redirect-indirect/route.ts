import { NextRequest, NextResponse } from 'next/server';

function redirectAfterLogin(returnTo: string, baseUrl: string) {
  return NextResponse.redirect(new URL(returnTo, baseUrl)); // EVAL-SINK
}

export function GET(request: NextRequest) {
  const returnTo = request.nextUrl.searchParams.get('returnTo') || '/';
  return redirectAfterLogin(returnTo, request.url);
}
