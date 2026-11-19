import { Body, Controller, Post } from '@nestjs/common';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';

const execFileAsync = promisify(execFile);

@Controller('api/cmdi-safe')
export class CmdiSafeController {
  @Post()
  async ping(@Body('host') host: string) {
    const { stdout } = await execFileAsync('ping', ['-c', '1', host]); // EVAL-SAFE
    return { output: stdout };
  }
}
