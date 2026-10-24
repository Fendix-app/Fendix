import { Controller, Get, Query } from '@nestjs/common';
import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function findUsersByName(name: string) {
  const result = await pool.query(`SELECT id, name, email FROM users WHERE name = '${name}'`); // EVAL-SINK
  return result.rows;
}

@Controller('api/sqli-indirect')
export class SqliIndirectController {
  @Get()
  async search(@Query('name') name: string) {
    const users = await findUsersByName(name);
    return users;
  }
}
