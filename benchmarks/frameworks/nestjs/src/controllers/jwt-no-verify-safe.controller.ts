import { Controller, ForbiddenException, Get, Headers, UnauthorizedException } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';

const JWT_SECRET = process.env.JWT_SECRET ?? '';

@Controller('api/jwt-no-verify-safe')
export class JwtNoVerifySafeController {
  @Get()
  adminSummary(@Headers('authorization') authorization: string) {
    const token = (authorization || '').replace(/^Bearer /, '');
    let claims: jwt.JwtPayload;
    try {
      claims = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }) as jwt.JwtPayload; // EVAL-SAFE
    } catch {
      throw new UnauthorizedException('Invalid token');
    }
    if (claims.role !== 'admin') {
      throw new ForbiddenException();
    }
    return { user: claims.sub, permissions: ['reports:read', 'users:write'] };
  }
}
