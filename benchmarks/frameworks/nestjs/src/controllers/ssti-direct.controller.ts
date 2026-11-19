import { Body, Controller, Post } from '@nestjs/common';
import * as ejs from 'ejs';

const SAMPLE_ORDER = { customer: 'Ada Lovelace', orderId: 'A-1001', total: '$42.00' };

@Controller('api/ssti-direct')
export class SstiDirectController {
  @Post()
  preview(@Body('template') template: string) {
    const html = ejs.render(template, SAMPLE_ORDER); // EVAL-SINK
    return { preview: html };
  }
}
