import { NextResponse } from 'next/server';

const FEATURED_ARTICLES = ['getting-started', 'billing', 'api-keys', 'webhooks', 'single-sign-on'];

export function GET() {
  const picks = [...FEATURED_ARTICLES].sort(() => Math.random() - 0.5).slice(0, 3); // EVAL-SAFE
  return NextResponse.json({ featured: picks });
}
