import { Controller, Get, Query, Res } from '@nestjs/common';
import { Response } from 'express';

@Controller('api/xss-direct')
export class XssDirectController {
  @Get()
  search(@Query('q') q: string, @Res() res: Response) {
    res.send(`<h1>Search results for ${q}</h1>`); // EVAL-SINK
  }
}
