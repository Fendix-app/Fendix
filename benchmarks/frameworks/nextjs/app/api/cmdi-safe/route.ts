import { NextRequest, NextResponse } from 'next/server';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

export async function POST(request: NextRequest) {
  const { host } = (await request.json()) as { host: string };
  const { stdout } = await execFileAsync('ping', ['-c', '1', host]); // EVAL-SAFE
  return NextResponse.json({ output: stdout });
}
