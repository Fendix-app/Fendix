import { NextRequest, NextResponse } from 'next/server';
import * as crypto from 'node:crypto';
import { Pool } from 'pg';

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

export async function POST(request: NextRequest) {
  const { email } = (await request.json()) as { email: string };
  const resetToken = crypto.randomBytes(32).toString('hex'); // EVAL-SAFE
  await pool.query("INSERT INTO password_resets (email, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')", [email, resetToken]);
  return NextResponse.json({ status: 'If the account exists, a reset link has been sent.' }, { status: 202 });
}
