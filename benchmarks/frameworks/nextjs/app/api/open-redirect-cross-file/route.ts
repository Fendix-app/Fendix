import { NextRequest } from 'next/server';
import { redirectAfterLogin } from '@/lib/open-redirect-cross-file';

export function GET(request: NextRequest) {
  const returnTo = request.nextUrl.searchParams.get('returnTo') || '/';
  return redirectAfterLogin(returnTo, request.url);
}
