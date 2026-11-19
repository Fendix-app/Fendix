import { Controller, Get, Query, Res } from '@nestjs/common';
import { Response } from 'express';
import { renderResults } from '../lib/xss-cross-file';

@Controller('api/xss-cross-file')
export class XssCrossFileController {
  @Get()
  search(@Query('q') q: string, @Res() res: Response) {
    renderResults(res, q);
  }
}
