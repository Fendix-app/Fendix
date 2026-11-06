import * as ejs from 'ejs';
import { NextRequest, NextResponse } from 'next/server';

const SAMPLE_ORDER = { customer: 'Ada Lovelace', orderId: 'A-1001', total: '$42.00' };

function renderPreview(template: string) {
  return ejs.render(template, SAMPLE_ORDER); // EVAL-SINK
}

export async function POST(request: NextRequest) {
  const { template } = (await request.json()) as { template: string };
  const html = renderPreview(template);
  return NextResponse.json({ preview: html });
}
