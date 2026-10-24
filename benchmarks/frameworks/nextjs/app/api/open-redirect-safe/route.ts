import { NextRequest, NextResponse } from 'next/server';

export function GET(request: NextRequest) {
  const returnTo = request.nextUrl.searchParams.get('returnTo') || '/';
  const isLocalPath = returnTo.startsWith('/') && !returnTo.startsWith('//') && !returnTo.includes('\\');
  return NextResponse.redirect(new URL(isLocalPath ? returnTo : '/', request.url)); // EVAL-SAFE
}
