import { NextResponse } from 'next/server';

const LOGIN_URL = 'https://accounts.example.com/login';

export function GET() {
  const response = NextResponse.redirect(LOGIN_URL); // EVAL-SAFE
  response.cookies.delete('session');
  return response;
}
