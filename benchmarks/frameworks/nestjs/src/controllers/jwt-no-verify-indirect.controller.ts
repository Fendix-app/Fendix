import { Controller, ForbiddenException, Get, Headers } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';

function getClaims(token: string) {
  return jwt.decode(token) as jwt.JwtPayload | null; // EVAL-SINK
}

@Controller('api/jwt-no-verify-indirect')
export class JwtNoVerifyIndirectController {
  @Get()
  adminSummary(@Headers('authorization') authorization: string) {
    const token = (authorization || '').replace(/^Bearer /, '');
    const claims = getClaims(token);
    if (!claims || claims.role !== 'admin') {
      throw new ForbiddenException();
    }
    return { user: claims.sub, permissions: ['reports:read', 'users:write'] };
  }
}
