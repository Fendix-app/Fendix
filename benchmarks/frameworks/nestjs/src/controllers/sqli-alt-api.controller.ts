import { Controller, Get, Query } from '@nestjs/common';
import mysql from 'mysql2/promise';

const pool = mysql.createPool({ uri: process.env.DATABASE_URL });

@Controller('api/sqli-alt-api')
export class SqliAltApiController {
  @Get()
  async search(@Query('name') name: string) {
    const [rows] = await pool.query("SELECT id, name, email FROM users WHERE name = '" + name + "'"); // EVAL-SINK
    return rows;
  }
}
