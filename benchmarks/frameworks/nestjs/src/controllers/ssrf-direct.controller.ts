import { Controller, Get, Query } from '@nestjs/common';

@Controller('api/ssrf-direct')
export class SsrfDirectController {
  @Get()
  async preview(@Query('url') url: string) {
    const upstream = await fetch(url); // EVAL-SINK
    return { status: upstream.status, body: await upstream.text() };
  }
}
