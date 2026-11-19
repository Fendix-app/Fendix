import { Controller, Get, Query } from '@nestjs/common';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');

async function readUpload(file: string) {
  const content = await fs.readFile(path.join(UPLOAD_DIR, file), 'utf8'); // EVAL-SINK
  return content;
}

@Controller('api/path-traversal-indirect')
export class PathTraversalIndirectController {
  @Get()
  async download(@Query('file') file: string) {
    const content = await readUpload(file);
    return { file, content };
  }
}
