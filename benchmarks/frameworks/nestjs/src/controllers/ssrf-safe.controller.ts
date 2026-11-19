import { BadRequestException, Controller, Get, Query } from '@nestjs/common';

const ALLOWED_HOSTS = new Set(['api.github.com', 'cdn.example.com']);

@Controller('api/ssrf-safe')
export class SsrfSafeController {
  @Get()
  async preview(@Query('url') url: string) {
    let target: URL;
    try {
      target = new URL(url);
    } catch {
      throw new BadRequestException('Invalid URL');
    }
    if (target.protocol !== 'https:' || !ALLOWED_HOSTS.has(target.hostname)) {
      throw new BadRequestException('Host not allowed');
    }
    const upstream = await fetch(target); // EVAL-SAFE
    return { status: upstream.status, body: await upstream.text() };
  }
}
