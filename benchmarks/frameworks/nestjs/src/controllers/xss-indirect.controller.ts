import { Controller, Get, Query, Res } from '@nestjs/common';
import { Response } from 'express';

function renderResults(res: Response, q: string) {
  res.send(`<h1>Search results for ${q}</h1>`); // EVAL-SINK
}

@Controller('api/xss-indirect')
export class XssIndirectController {
  @Get()
  search(@Query('q') q: string, @Res() res: Response) {
    renderResults(res, q);
  }
}
