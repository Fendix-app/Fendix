import axios from 'axios';
import { NextRequest, NextResponse } from 'next/server';

export async function GET(request: NextRequest) {
  const url = request.nextUrl.searchParams.get('url') ?? '';
  const upstream = await axios.get(url, { responseType: 'text' }); // EVAL-SINK
  return NextResponse.json({ status: upstream.status, body: upstream.data });
}
