import { Controller, Get, Query, StreamableFile } from '@nestjs/common';
import * as fs from 'node:fs';
import * as path from 'node:path';

const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');

@Controller('api/path-traversal-alt-api')
export class PathTraversalAltApiController {
  @Get()
  download(@Query('file') file: string) {
    const stream = fs.createReadStream(path.join(UPLOAD_DIR, file)); // EVAL-SINK
    return new StreamableFile(stream, { type: 'application/octet-stream' });
  }
}
