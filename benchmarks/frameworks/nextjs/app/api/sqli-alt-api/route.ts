import mysql from 'mysql2/promise';
import { NextRequest, NextResponse } from 'next/server';

const pool = mysql.createPool({ uri: process.env.DATABASE_URL });

export async function GET(request: NextRequest) {
  const name = request.nextUrl.searchParams.get('name') ?? '';
  const [rows] = await pool.query("SELECT id, name, email FROM users WHERE name = '" + name + "'"); // EVAL-SINK
  return NextResponse.json(rows);
}
