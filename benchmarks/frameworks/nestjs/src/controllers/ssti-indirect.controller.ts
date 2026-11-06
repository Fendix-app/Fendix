import { Body, Controller, Post } from '@nestjs/common';
import * as ejs from 'ejs';

const SAMPLE_ORDER = { customer: 'Ada Lovelace', orderId: 'A-1001', total: '$42.00' };

function renderPreview(template: string) {
  return ejs.render(template, SAMPLE_ORDER); // EVAL-SINK
}

@Controller('api/ssti-indirect')
export class SstiIndirectController {
  @Post()
  preview(@Body('template') template: string) {
    const html = renderPreview(template);
    return { preview: html };
  }
}
