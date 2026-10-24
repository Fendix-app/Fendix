import { NextRequest } from 'next/server';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { Readable } from 'node:stream';

const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');

export function GET(request: NextRequest) {
  const file = request.nextUrl.searchParams.get('file') ?? '';
  const stream = fs.createReadStream(path.join(UPLOAD_DIR, file)); // EVAL-SINK
  return new Response(Readable.toWeb(stream) as ReadableStream, { headers: { 'Content-Type': 'application/octet-stream' } });
}
