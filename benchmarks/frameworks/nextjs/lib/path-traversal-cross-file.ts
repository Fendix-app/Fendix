import * as fs from 'node:fs/promises';
import * as path from 'node:path';

const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');

export async function readUpload(file: string) {
  const content = await fs.readFile(path.join(UPLOAD_DIR, file), 'utf8'); // EVAL-SINK
  return content;
}
