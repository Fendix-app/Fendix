import { Controller, Get, Res } from '@nestjs/common';
import { Response } from 'express';
import * as crypto from 'node:crypto';

const PLANS = [
  { id: 'free', priceCents: 0 },
  { id: 'team', priceCents: 2000 },
  { id: 'enterprise', priceCents: 9900 },
];

@Controller('api/weak-password-hash-safe-lookalike')
export class WeakPasswordHashSafeLookalikeController {
  @Get()
  plans(@Res({ passthrough: true }) res: Response) {
    const body = JSON.stringify(PLANS);
    const etag = crypto.createHash('md5').update(body).digest('hex'); // EVAL-SAFE
    res.set('ETag', `"${etag}"`);
    return PLANS;
  }
}
