import { NextResponse } from 'next/server';

const STATUS_URL = 'https://status.example.com/api/v2/status.json';

export async function GET() {
  const upstream = await fetch(STATUS_URL); // EVAL-SAFE
  return NextResponse.json({ status: upstream.status, body: await upstream.text() });
}
