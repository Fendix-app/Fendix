import { Body, Controller, Post } from '@nestjs/common';
import { execSync } from 'node:child_process';

@Controller('api/cmdi-alt-api')
export class CmdiAltApiController {
  @Post()
  ping(@Body('host') host: string) {
    const output = execSync(`ping -c 1 ${host}`, { encoding: 'utf8' }); // EVAL-SINK
    return { output };
  }
}
