import { NextRequest, NextResponse } from 'next/server';
import { execSync } from 'node:child_process';

export async function POST(request: NextRequest) {
  const { host } = (await request.json()) as { host: string };
  const output = execSync(`ping -c 1 ${host}`, { encoding: 'utf8' }); // EVAL-SINK
  return NextResponse.json({ output });
}
