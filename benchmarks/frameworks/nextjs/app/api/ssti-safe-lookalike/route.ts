import * as ejs from 'ejs';
import { NextResponse } from 'next/server';

const FOOTER_TEMPLATE = '<footer>&copy; <%= year %> Acme Inc. All rights reserved.</footer>';

export function GET() {
  const html = ejs.render(FOOTER_TEMPLATE, { year: new Date().getFullYear() }); // EVAL-SAFE
  return NextResponse.json({ footer: html });
}
