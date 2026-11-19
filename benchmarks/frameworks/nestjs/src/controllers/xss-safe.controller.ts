import { Controller, Get, Query, Res } from '@nestjs/common';
import escapeHtml from 'escape-html';
import { Response } from 'express';

@Controller('api/xss-safe')
export class XssSafeController {
  @Get()
  search(@Query('q') q: string, @Res() res: Response) {
    res.send(`<h1>Search results for ${escapeHtml(q)}</h1>`); // EVAL-SAFE
  }
}
