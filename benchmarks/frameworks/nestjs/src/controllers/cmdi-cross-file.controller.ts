import { Body, Controller, Post } from '@nestjs/common';
import { pingHost } from '../lib/cmdi-cross-file';

@Controller('api/cmdi-cross-file')
export class CmdiCrossFileController {
  @Post()
  async ping(@Body('host') host: string) {
    const output = await pingHost(host);
    return { output };
  }
}
