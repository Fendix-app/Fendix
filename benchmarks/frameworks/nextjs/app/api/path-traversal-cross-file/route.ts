import { NextRequest, NextResponse } from 'next/server';
import { readUpload } from '@/lib/path-traversal-cross-file';

export async function GET(request: NextRequest) {
  const file = request.nextUrl.searchParams.get('file') ?? '';
  const content = await readUpload(file);
  return NextResponse.json({ file, content });
}
