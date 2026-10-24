import { Controller, Get, Query } from '@nestjs/common';
import { findUsersByName } from '../lib/sqli-cross-file';

@Controller('api/sqli-cross-file')
export class SqliCrossFileController {
  @Get()
  async search(@Query('name') name: string) {
    const users = await findUsersByName(name);
    return users;
  }
}
