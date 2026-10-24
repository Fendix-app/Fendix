import { Controller, Get, Query } from '@nestjs/common';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');

@Controller('api/path-traversal-direct')
export class PathTraversalDirectController {
  @Get()
  async download(@Query('file') file: string) {
    const content = await fs.readFile(path.join(UPLOAD_DIR, file), 'utf8'); // EVAL-SINK
    return { file, content };
  }
}
