import { Body, Controller, Post } from '@nestjs/common';
import * as ejs from 'ejs';

const SAMPLE_ORDER = { customer: 'Ada Lovelace', orderId: 'A-1001', total: '$42.00' };
const ORDER_TEMPLATE = '<p>Hi <%= customer %>, order <%= orderId %> totals <%= total %>.</p>';

@Controller('api/ssti-safe')
export class SstiSafeController {
  @Post()
  preview(@Body('customer') customer: string) {
    const html = ejs.render(ORDER_TEMPLATE, { ...SAMPLE_ORDER, customer }); // EVAL-SAFE
    return { preview: html };
  }
}
