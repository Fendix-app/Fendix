import * as bcrypt from 'bcrypt';
import { NextRequest, NextResponse } from 'next/server';
import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export async function POST(request: NextRequest) {
  const { email, password } = (await request.json()) as { email: string; password: string };
  const passwordHash = await bcrypt.hash(password, 12); // EVAL-SAFE
  await pool.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [email, passwordHash]);
  return NextResponse.json({ email }, { status: 201 });
}
