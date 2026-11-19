import { Controller, Get, Query } from '@nestjs/common';
import axios from 'axios';

@Controller('api/ssrf-alt-api')
export class SsrfAltApiController {
  @Get()
  async preview(@Query('url') url: string) {
    const upstream = await axios.get(url, { responseType: 'text' }); // EVAL-SINK
    return { status: upstream.status, body: upstream.data };
  }
}
