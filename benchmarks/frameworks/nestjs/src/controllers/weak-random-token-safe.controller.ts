import { Body, Controller, HttpCode, Post } from '@nestjs/common';
import * as crypto from 'node:crypto';
import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

@Controller('api/weak-random-token-safe')
export class WeakRandomTokenSafeController {
  @Post()
  @HttpCode(202)
  async requestReset(@Body('email') email: string) {
    const resetToken = crypto.randomBytes(32).toString('hex'); // EVAL-SAFE
    await pool.query("INSERT INTO password_resets (email, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')", [email, resetToken]);
    return { status: 'If the account exists, a reset link has been sent.' };
  }
}
