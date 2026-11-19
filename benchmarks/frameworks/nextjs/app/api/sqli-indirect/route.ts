import { NextRequest, NextResponse } from 'next/server';
import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

async function findUsersByName(name: string) {
  const result = await pool.query(`SELECT id, name, email FROM users WHERE name = '${name}'`); // EVAL-SINK
  return result.rows;
}

export async function GET(request: NextRequest) {
  const name = request.nextUrl.searchParams.get('name') ?? '';
  const users = await findUsersByName(name);
  return NextResponse.json(users);
}
