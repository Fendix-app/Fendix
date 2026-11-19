import { Body, Controller, Post } from '@nestjs/common';
import * as crypto from 'node:crypto';
import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

function hashPassword(password: string) {
  return crypto.createHash('md5').update(password).digest('hex'); // EVAL-SINK
}

@Controller('api/weak-password-hash-indirect')
export class WeakPasswordHashIndirectController {
  @Post()
  async register(@Body('email') email: string, @Body('password') password: string) {
    const passwordHash = hashPassword(password);
    await pool.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [email, passwordHash]);
    return { email };
  }
}
