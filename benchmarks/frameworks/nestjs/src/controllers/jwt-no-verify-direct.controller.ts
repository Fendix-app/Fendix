import { Controller, ForbiddenException, Get, Headers } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';

@Controller('api/jwt-no-verify-direct')
export class JwtNoVerifyDirectController {
  @Get()
  adminSummary(@Headers('authorization') authorization: string) {
    const token = (authorization || '').replace(/^Bearer /, '');
    const claims = jwt.decode(token) as jwt.JwtPayload | null; // EVAL-SINK
    if (!claims || claims.role !== 'admin') {
      throw new ForbiddenException();
    }
    return { user: claims.sub, permissions: ['reports:read', 'users:write'] };
  }
}
