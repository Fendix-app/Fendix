import { BadRequestException, Controller, Get, Query } from '@nestjs/common';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';

const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');

@Controller('api/path-traversal-safe')
export class PathTraversalSafeController {
  @Get()
  async download(@Query('file') file: string) {
    const filePath = path.resolve(UPLOAD_DIR, file);
    if (!filePath.startsWith(UPLOAD_DIR + path.sep)) {
      throw new BadRequestException('Invalid file name');
    }
    const content = await fs.readFile(filePath, 'utf8'); // EVAL-SAFE
    return { file, content };
  }
}
