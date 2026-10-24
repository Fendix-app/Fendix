import { Controller, ForbiddenException, Get, Headers, UnauthorizedException } from '@nestjs/common';
import * as jwt from 'jsonwebtoken';

const PUBLIC_KEYS = new Map<string, string | undefined>([
  ['auth-2026-01', process.env.JWT_PUBLIC_KEY_CURRENT],
  ['auth-2025-07', process.env.JWT_PUBLIC_KEY_PREVIOUS],
]);

@Controller('api/jwt-no-verify-safe-lookalike')
export class JwtNoVerifySafeLookalikeController {
  @Get()
  adminSummary(@Headers('authorization') authorization: string) {
    const token = (authorization || '').replace(/^Bearer /, '');
    const decoded = jwt.decode(token, { complete: true }); // EVAL-SAFE
    const publicKey = decoded?.header.kid ? PUBLIC_KEYS.get(decoded.header.kid) : undefined;
    if (!publicKey) {
      throw new UnauthorizedException('Unknown signing key');
    }
    let claims: jwt.JwtPayload;
    try {
      claims = jwt.verify(token, publicKey, { algorithms: ['RS256'] }) as jwt.JwtPayload;
    } catch {
      throw new UnauthorizedException('Invalid token');
    }
    if (claims.role !== 'admin') {
      throw new ForbiddenException();
    }
    return { user: claims.sub, permissions: ['reports:read', 'users:write'] };
  }
}
