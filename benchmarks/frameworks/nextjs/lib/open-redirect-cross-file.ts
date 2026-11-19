import { NextResponse } from 'next/server';

export function redirectAfterLogin(returnTo: string, baseUrl: string) {
  return NextResponse.redirect(new URL(returnTo, baseUrl)); // EVAL-SINK
}
