import { Controller, Get, Query, Res } from '@nestjs/common';
import { Response } from 'express';

@Controller('api/open-redirect-alt-api')
export class OpenRedirectAltApiController {
  @Get()
  continueAfterLogin(@Query('returnTo') returnTo: string, @Res() res: Response) {
    const target = returnTo || '/';
    res.writeHead(302, { Location: target }); // EVAL-SINK
    res.end();
  }
}
