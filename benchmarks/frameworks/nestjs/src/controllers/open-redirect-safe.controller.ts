import { Controller, Get, Query, Res } from '@nestjs/common';
import { Response } from 'express';

@Controller('api/open-redirect-safe')
export class OpenRedirectSafeController {
  @Get()
  continueAfterLogin(@Query('returnTo') returnTo: string, @Res() res: Response) {
    const target = returnTo || '/';
    const isLocalPath = target.startsWith('/') && !target.startsWith('//') && !target.includes('\\');
    res.redirect(isLocalPath ? target : '/'); // EVAL-SAFE
  }
}
