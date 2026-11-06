import { Controller, Get, Query } from '@nestjs/common';
import { readUpload } from '../lib/path-traversal-cross-file';

@Controller('api/path-traversal-cross-file')
export class PathTraversalCrossFileController {
  @Get()
  async download(@Query('file') file: string) {
    const content = await readUpload(file);
    return { file, content };
  }
}
