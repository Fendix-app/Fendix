import { NextRequest, NextResponse } from 'next/server';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const execAsync = promisify(exec);

export async function POST(request: NextRequest) {
  const { host } = (await request.json()) as { host: string };
  const { stdout } = await execAsync(`ping -c 1 ${host}`); // EVAL-SINK
  return NextResponse.json({ output: stdout });
}
