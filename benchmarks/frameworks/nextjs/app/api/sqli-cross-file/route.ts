import { NextRequest, NextResponse } from 'next/server';
import { findUsersByName } from '@/lib/sqli-cross-file';

export async function GET(request: NextRequest) {
  const name = request.nextUrl.searchParams.get('name') ?? '';
  const users = await findUsersByName(name);
  return NextResponse.json(users);
}
