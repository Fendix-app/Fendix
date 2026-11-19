import { Body, Controller, Post } from '@nestjs/common';
import * as crypto from 'node:crypto';
import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

@Controller('api/weak-password-hash-direct')
export class WeakPasswordHashDirectController {
  @Post()
  async register(@Body('email') email: string, @Body('password') password: string) {
    const passwordHash = crypto.createHash('md5').update(password).digest('hex'); // EVAL-SINK
    await pool.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [email, passwordHash]);
    return { email };
  }
}
