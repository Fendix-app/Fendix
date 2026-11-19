import { Body, Controller, Post } from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

@Controller('api/weak-password-hash-safe')
export class WeakPasswordHashSafeController {
  @Post()
  async register(@Body('email') email: string, @Body('password') password: string) {
    const passwordHash = await bcrypt.hash(password, 12); // EVAL-SAFE
    await pool.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [email, passwordHash]);
    return { email };
  }
}
