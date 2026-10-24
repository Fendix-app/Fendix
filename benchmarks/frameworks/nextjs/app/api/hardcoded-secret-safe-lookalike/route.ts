import { NextResponse } from 'next/server';

const BUILD_DIGEST = '4b7e19c2a05d83f6e2c8714b9d36fa057c1e48b2d9a3605f1e8bc274f30a96d5'; // EVAL-SAFE

export function GET() {
  return NextResponse.json({ algorithm: 'sha256', digest: BUILD_DIGEST });
}
