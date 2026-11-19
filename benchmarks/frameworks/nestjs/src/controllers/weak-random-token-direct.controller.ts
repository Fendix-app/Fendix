import { Body, Controller, HttpCode, Post } from '@nestjs/common';
import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

@Controller('api/weak-random-token-direct')
export class WeakRandomTokenDirectController {
  @Post()
  @HttpCode(202)
  async requestReset(@Body('email') email: string) {
    const resetToken = Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2); // EVAL-SINK
    await pool.query("INSERT INTO password_resets (email, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')", [email, resetToken]);
    return { status: 'If the account exists, a reset link has been sent.' };
  }
}
