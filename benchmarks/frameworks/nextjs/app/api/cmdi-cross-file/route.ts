import { NextRequest, NextResponse } from 'next/server';
import { pingHost } from '@/lib/cmdi-cross-file';

export async function POST(request: NextRequest) {
  const { host } = (await request.json()) as { host: string };
  const output = await pingHost(host);
  return NextResponse.json({ output });
}
