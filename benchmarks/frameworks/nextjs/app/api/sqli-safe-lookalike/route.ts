import { NextResponse } from 'next/server';
import { Pool } from 'pg';

const DEFAULT_ROLE = 'member';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export async function GET() {
  const result = await pool.query(`SELECT id, name, email FROM users WHERE role = '${DEFAULT_ROLE}' ORDER BY name`); // EVAL-SAFE
  return NextResponse.json(result.rows);
}
