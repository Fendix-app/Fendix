import { Controller, Get } from '@nestjs/common';
import * as ejs from 'ejs';

const FOOTER_TEMPLATE = '<footer>&copy; <%= year %> Acme Inc. All rights reserved.</footer>';

@Controller('api/ssti-safe-lookalike')
export class SstiSafeLookalikeController {
  @Get()
  footer() {
    const html = ejs.render(FOOTER_TEMPLATE, { year: new Date().getFullYear() }); // EVAL-SAFE
    return { footer: html };
  }
}
