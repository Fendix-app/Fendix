import { Controller, Get } from '@nestjs/common';
import { exec } from 'node:child_process';
import { promisify } from 'node:util';

const LOG_DIR = '/var/log/app';

const execAsync = promisify(exec);

@Controller('api/cmdi-safe-lookalike')
export class CmdiSafeLookalikeController {
  @Get()
  async diskUsage() {
    const { stdout } = await execAsync(`du -sh ${LOG_DIR}`); // EVAL-SAFE
    return { usage: stdout.trim() };
  }
}
