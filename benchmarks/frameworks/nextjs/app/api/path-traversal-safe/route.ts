import { NextRequest, NextResponse } from 'next/server';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');

export async function GET(request: NextRequest) {
  const file = request.nextUrl.searchParams.get('file') ?? '';
  const filePath = path.resolve(UPLOAD_DIR, file);
  if (!filePath.startsWith(UPLOAD_DIR + path.sep)) {
    return NextResponse.json({ error: 'Invalid file name' }, { status: 400 });
  }
  const content = await fs.readFile(filePath, 'utf8'); // EVAL-SAFE
  return NextResponse.json({ file, content });
}
