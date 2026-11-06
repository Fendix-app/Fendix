import { Controller, Get } from '@nestjs/common';
import { Pool } from 'pg';

const DEFAULT_ROLE = 'member';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

@Controller('api/sqli-safe-lookalike')
export class SqliSafeLookalikeController {
  @Get()
  async listMembers() {
    const result = await pool.query(`SELECT id, name, email FROM users WHERE role = '${DEFAULT_ROLE}' ORDER BY name`); // EVAL-SAFE
    return result.rows;
  }
}
