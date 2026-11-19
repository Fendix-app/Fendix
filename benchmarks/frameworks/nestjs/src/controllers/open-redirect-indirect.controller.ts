import { Controller, Get, Query, Res } from '@nestjs/common';
import { Response } from 'express';

function redirectAfterLogin(res: Response, returnTo: string) {
  res.redirect(returnTo); // EVAL-SINK
}

@Controller('api/open-redirect-indirect')
export class OpenRedirectIndirectController {
  @Get()
  continueAfterLogin(@Query('returnTo') returnTo: string, @Res() res: Response) {
    const target = returnTo || '/';
    redirectAfterLogin(res, target);
  }
}
