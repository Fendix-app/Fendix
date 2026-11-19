import { Controller, Get, Query } from '@nestjs/common';

async function fetchPreview(url: string) {
  const upstream = await fetch(url); // EVAL-SINK
  return { status: upstream.status, body: await upstream.text() };
}

@Controller('api/ssrf-indirect')
export class SsrfIndirectController {
  @Get()
  async preview(@Query('url') url: string) {
    const preview = await fetchPreview(url);
    return preview;
  }
}
