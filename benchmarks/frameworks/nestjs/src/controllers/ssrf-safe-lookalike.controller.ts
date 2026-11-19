import { Controller, Get } from '@nestjs/common';

const STATUS_URL = 'https://status.example.com/api/v2/status.json';

@Controller('api/ssrf-safe-lookalike')
export class SsrfSafeLookalikeController {
  @Get()
  async status() {
    const upstream = await fetch(STATUS_URL); // EVAL-SAFE
    return { status: upstream.status, body: await upstream.text() };
  }
}
