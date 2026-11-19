import { Body, Controller, Post } from '@nestjs/common';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const execAsync = promisify(exec);

async function pingHost(host: string) {
  const { stdout } = await execAsync(`ping -c 1 ${host}`); // EVAL-SINK
  return stdout;
}

@Controller('api/cmdi-indirect')
export class CmdiIndirectController {
  @Post()
  async ping(@Body('host') host: string) {
    const output = await pingHost(host);
    return { output };
  }
}
