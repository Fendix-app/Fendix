import { Controller, Get, Res } from '@nestjs/common';
import { Response } from 'express';

const SITE_NAME = 'Acme Docs';

@Controller('api/xss-safe-lookalike')
export class XssSafeLookalikeController {
  @Get()
  welcome(@Res() res: Response) {
    res.send(`<h1>Welcome to ${SITE_NAME}</h1>`); // EVAL-SAFE
  }
}
