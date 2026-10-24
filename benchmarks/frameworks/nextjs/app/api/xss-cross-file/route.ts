import { NextRequest } from 'next/server';
import { renderResults } from '@/lib/xss-cross-file';

export function GET(request: NextRequest) {
  const q = request.nextUrl.searchParams.get('q') ?? '';
  return renderResults(q);
}
