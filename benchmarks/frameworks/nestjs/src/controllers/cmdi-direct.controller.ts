import { Body, Controller, Post } from '@nestjs/common';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const execAsync = promisify(exec);

@Controller('api/cmdi-direct')
export class CmdiDirectController {
  @Post()
  async ping(@Body('host') host: string) {
    const { stdout } = await execAsync(`ping -c 1 ${host}`); // EVAL-SINK
    return { output: stdout };
  }
}
