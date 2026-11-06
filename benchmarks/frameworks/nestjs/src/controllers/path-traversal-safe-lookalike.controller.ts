import { Controller, Get } from '@nestjs/common';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

const CONTENT_DIR = path.resolve(process.cwd(), 'content');
const TERMS_FILE = 'terms-of-service.md';

@Controller('api/path-traversal-safe-lookalike')
export class PathTraversalSafeLookalikeController {
  @Get()
  async terms() {
    const content = await fs.readFile(path.join(CONTENT_DIR, TERMS_FILE), 'utf8'); // EVAL-SAFE
    return { file: TERMS_FILE, content };
  }
}
