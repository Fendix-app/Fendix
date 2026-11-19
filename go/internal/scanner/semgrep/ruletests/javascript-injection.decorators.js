// Rule tests for rules/javascript-injection.yaml: every NestJS parameter
// decorator each taint rule reads as a source, one handler per (rule,
// decorator). Each handler is marked `// source: <rule> @<decorator> <label>`;
// TestJavaScriptDecoratorSourcesHaveCases (../js_mirror_test.go) requires a
// marked case for every decorator item of every rule, in this file and its
// .js mirror. No parameter is named req or request and no handler is named
// after an HTTP method, so the Express and Next.js sources cannot report
// these lines: only the decorator source can. See README.md.

import { Body, Controller, Get, Headers, Param, Query, Req } from '@nestjs/common';

import { exec } from 'node:child_process';
import ejs from 'ejs';
import { Pool } from 'pg';

const pool = new Pool();

@Controller('injection-decorators')
export class InjectionDecoratorSources {
  // source: js-sqli-taint @Query INPUT
  @Get('viasqliquery')
  async viaSqliQuery(@Query('k') value        ) {
    // ruleid: js-sqli-taint, js-sqli-sink
    return pool.query('SELECT * FROM users WHERE name = ' + value);
  }

  // source: js-sqli-taint @Param INPUT
  @Get('viasqliparam')
  async viaSqliParam(@Param('k') value        ) {
    // ruleid: js-sqli-taint, js-sqli-sink
    return pool.query('SELECT * FROM users WHERE name = ' + value);
  }

  // source: js-sqli-taint @Body INPUT
  @Get('viasqlibody')
  async viaSqliBody(@Body('k') value        ) {
    // ruleid: js-sqli-taint, js-sqli-sink
    return pool.query('SELECT * FROM users WHERE name = ' + value);
  }

  // source: js-sqli-taint @Headers INPUT
  @Get('viasqliheaders')
  async viaSqliHeaders(@Headers('x-k') value        ) {
    // ruleid: js-sqli-taint, js-sqli-sink
    return pool.query('SELECT * FROM users WHERE name = ' + value);
  }

  // source: js-sqli-taint @Req INPUT
  @Get('viasqlireqr')
  async viaSqliReqR(@Req() r         ) {
    // ruleid: js-sqli-taint, js-sqli-sink
    return pool.query('SELECT * FROM users WHERE name = ' + r.query.k);
  }

  // source: js-sqli-taint @Req INPUT
  @Get('viasqlireqhttpreq')
  async viaSqliReqHttpreq(@Req() httpReq         ) {
    // ruleid: js-sqli-taint, js-sqli-sink
    return pool.query('SELECT * FROM users WHERE name = ' + httpReq.body.k);
  }

  // source: js-cmdi-taint @Query INPUT
  @Get('viacmdiquery')
  async viaCmdiQuery(@Query('k') value        ) {
    // ruleid: js-cmdi-taint, js-cmdi-sink
    return exec('ping -c 1 ' + value, () => undefined);
  }

  // source: js-cmdi-taint @Param INPUT
  @Get('viacmdiparam')
  async viaCmdiParam(@Param('k') value        ) {
    // ruleid: js-cmdi-taint, js-cmdi-sink
    return exec('ping -c 1 ' + value, () => undefined);
  }

  // source: js-cmdi-taint @Body INPUT
  @Get('viacmdibody')
  async viaCmdiBody(@Body('k') value        ) {
    // ruleid: js-cmdi-taint, js-cmdi-sink
    return exec('ping -c 1 ' + value, () => undefined);
  }

  // source: js-cmdi-taint @Headers INPUT
  @Get('viacmdiheaders')
  async viaCmdiHeaders(@Headers('x-k') value        ) {
    // ruleid: js-cmdi-taint, js-cmdi-sink
    return exec('ping -c 1 ' + value, () => undefined);
  }

  // source: js-cmdi-taint @Req INPUT
  @Get('viacmdireqr')
  async viaCmdiReqR(@Req() r         ) {
    // ruleid: js-cmdi-taint, js-cmdi-sink
    return exec('ping -c 1 ' + r.query.k, () => undefined);
  }

  // source: js-cmdi-taint @Req INPUT
  @Get('viacmdireqhttpreq')
  async viaCmdiReqHttpreq(@Req() httpReq         ) {
    // ruleid: js-cmdi-taint, js-cmdi-sink
    return exec('ping -c 1 ' + httpReq.body.k, () => undefined);
  }

  // source: js-ssti-taint @Query INPUT
  @Get('viasstiquery')
  async viaSstiQuery(@Query('k') value        ) {
    // ruleid: js-ssti-taint, js-ssti-sink
    return ejs.render(value, { year: 2026 });
  }

  // source: js-ssti-taint @Param INPUT
  @Get('viasstiparam')
  async viaSstiParam(@Param('k') value        ) {
    // ruleid: js-ssti-taint, js-ssti-sink
    return ejs.render(value, { year: 2026 });
  }

  // source: js-ssti-taint @Body INPUT
  @Get('viasstibody')
  async viaSstiBody(@Body('k') value        ) {
    // ruleid: js-ssti-taint, js-ssti-sink
    return ejs.render(value, { year: 2026 });
  }

  // source: js-ssti-taint @Headers INPUT
  @Get('viasstiheaders')
  async viaSstiHeaders(@Headers('x-k') value        ) {
    // ruleid: js-ssti-taint, js-ssti-sink
    return ejs.render(value, { year: 2026 });
  }

  // source: js-ssti-taint @Req INPUT
  @Get('viasstireqr')
  async viaSstiReqR(@Req() r         ) {
    // ruleid: js-ssti-taint
    return ejs.render(r.query.k, { year: 2026 });
  }

  // source: js-ssti-taint @Req INPUT
  @Get('viasstireqhttpreq')
  async viaSstiReqHttpreq(@Req() httpReq         ) {
    // ruleid: js-ssti-taint
    return ejs.render(httpReq.body.k, { year: 2026 });
  }
}
