import { NextRequest, NextResponse } from 'next/server';
import * as crypto from 'node:crypto';
import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

function hashPassword(password: string) {
  return crypto.createHash('md5').update(password).digest('hex'); // EVAL-SINK
}

export async function POST(request: NextRequest) {
  const { email, password } = (await request.json()) as { email: string; password: string };
  const passwordHash = hashPassword(password);
  await pool.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [email, passwordHash]);
  return NextResponse.json({ email }, { status: 201 });
}
