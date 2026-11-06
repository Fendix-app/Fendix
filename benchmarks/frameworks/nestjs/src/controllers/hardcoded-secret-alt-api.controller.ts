import { Controller, Get } from '@nestjs/common';
import { Pool } from 'pg';

const DATABASE_URL = 'postgres://app:__EVAL_DB_PASSWORD__@db.internal:5432/app'; // EVAL-SINK

const pool = new Pool({ connectionString: DATABASE_URL });

@Controller('api/hardcoded-secret-alt-api')
export class HardcodedSecretAltApiController {
  @Get()
  async userCount() {
    const result = await pool.query('SELECT count(*)::int AS total FROM users');
    return { users: result.rows[0].total };
  }
}
