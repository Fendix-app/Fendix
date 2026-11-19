import { NextRequest, NextResponse } from 'next/server';
import { fetchPreview } from '@/lib/ssrf-cross-file';

export async function GET(request: NextRequest) {
  const url = request.nextUrl.searchParams.get('url') ?? '';
  const preview = await fetchPreview(url);
  return NextResponse.json(preview);
}
