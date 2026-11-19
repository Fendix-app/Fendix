import * as ejs from 'ejs';
import { NextRequest, NextResponse } from 'next/server';

const SAMPLE_ORDER = { customer: 'Ada Lovelace', orderId: 'A-1001', total: '$42.00' };
const ORDER_TEMPLATE = '<p>Hi <%= customer %>, order <%= orderId %> totals <%= total %>.</p>';

export async function POST(request: NextRequest) {
  const { customer } = (await request.json()) as { customer: string };
  const html = ejs.render(ORDER_TEMPLATE, { ...SAMPLE_ORDER, customer }); // EVAL-SAFE
  return NextResponse.json({ preview: html });
}
