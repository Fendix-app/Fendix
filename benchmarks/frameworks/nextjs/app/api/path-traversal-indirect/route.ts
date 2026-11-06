import { NextRequest, NextResponse } from 'next/server';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');

async function readUpload(file: string) {
  const content = await fs.readFile(path.join(UPLOAD_DIR, file), 'utf8'); // EVAL-SINK
  return content;
}

export async function GET(request: NextRequest) {
  const file = request.nextUrl.searchParams.get('file') ?? '';
  const content = await readUpload(file);
  return NextResponse.json({ file, content });
}
