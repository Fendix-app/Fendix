import { NextResponse } from 'next/server';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

const CONTENT_DIR = path.resolve(process.cwd(), 'content');
const TERMS_FILE = 'terms-of-service.md';

export async function GET() {
  const content = await fs.readFile(path.join(CONTENT_DIR, TERMS_FILE), 'utf8'); // EVAL-SAFE
  return NextResponse.json({ file: TERMS_FILE, content });
}
