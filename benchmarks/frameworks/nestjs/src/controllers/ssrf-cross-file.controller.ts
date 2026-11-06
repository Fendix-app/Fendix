import { Controller, Get, Query } from '@nestjs/common';
import { fetchPreview } from '../lib/ssrf-cross-file';

@Controller('api/ssrf-cross-file')
export class SsrfCrossFileController {
  @Get()
  async preview(@Query('url') url: string) {
    const preview = await fetchPreview(url);
    return preview;
  }
}
