import { Controller, Get, Query, Res } from '@nestjs/common';
import { Response } from 'express';

@Controller('api/xss-alt-api')
export class XssAltApiController {
  @Get()
  search(@Query('q') q: string, @Res() res: Response) {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.write(`<h1>Search results for ${q}</h1>`); // EVAL-SINK
    res.end();
  }
}
