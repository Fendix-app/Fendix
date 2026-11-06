import { NextResponse } from 'next/server';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const LOG_DIR = '/var/log/app';

const execAsync = promisify(exec);

export async function GET() {
  const { stdout } = await execAsync(`du -sh ${LOG_DIR}`); // EVAL-SAFE
  return NextResponse.json({ usage: stdout.trim() });
}
