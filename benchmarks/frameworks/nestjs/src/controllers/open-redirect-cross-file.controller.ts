import { Controller, Get, Query, Res } from '@nestjs/common';
import { Response } from 'express';
import { redirectAfterLogin } from '../lib/open-redirect-cross-file';

@Controller('api/open-redirect-cross-file')
export class OpenRedirectCrossFileController {
  @Get()
  continueAfterLogin(@Query('returnTo') returnTo: string, @Res() res: Response) {
    const target = returnTo || '/';
    redirectAfterLogin(res, target);
  }
}
