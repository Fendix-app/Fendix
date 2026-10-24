import { Controller, Get, Query, Res } from '@nestjs/common';
import { Response } from 'express';

@Controller('api/open-redirect-direct')
export class OpenRedirectDirectController {
  @Get()
  continueAfterLogin(@Query('returnTo') returnTo: string, @Res() res: Response) {
    const target = returnTo || '/';
    res.redirect(target); // EVAL-SINK
  }
}
