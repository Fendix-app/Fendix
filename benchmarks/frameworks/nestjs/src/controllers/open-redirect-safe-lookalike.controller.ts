import { Controller, Get, Res } from '@nestjs/common';
import { Response } from 'express';

const LOGIN_URL = 'https://accounts.example.com/login';

@Controller('api/open-redirect-safe-lookalike')
export class OpenRedirectSafeLookalikeController {
  @Get()
  logout(@Res() res: Response) {
    res.clearCookie('session');
    res.redirect(LOGIN_URL); // EVAL-SAFE
  }
}
