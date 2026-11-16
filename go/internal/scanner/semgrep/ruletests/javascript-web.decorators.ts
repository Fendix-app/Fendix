// Rule tests for rules/javascript-web.yaml: every NestJS parameter
// decorator each taint rule reads as a source, one handler per (rule,
// decorator). Each handler is marked `// source: <rule> @<decorator> <label>`;
// TestJavaScriptDecoratorSourcesHaveCases (../js_mirror_test.go) requires a
// marked case for every decorator item of every rule, in this file and its
// .js mirror. No parameter is named req or request and no handler is named
// after an HTTP method, so the Express and Next.js sources cannot report
// these lines: only the decorator source can. See README.md.

import { Body, Controller, Get, Headers, Param, Query, Req, Res } from '@nestjs/common';
import type { Request, Response } from 'express';
import * as fsp from 'node:fs/promises';
import * as path from 'node:path';

const UPLOAD_DIR = path.resolve(process.cwd(), 'uploads');

@Controller('web-decorators')
export class WebDecoratorSources {
  // source: js-xss-taint @Query INPUT
  @Get('viaxssquery')
  async viaXssQuery(@Query('k') value: string, @Res() res: Response) {
    // ruleid: js-xss-taint, js-xss-sink
    res.send('<p>' + value + '</p>');
  }

  // source: js-xss-taint @Param INPUT
  @Get('viaxssparam')
  async viaXssParam(@Param('k') value: string, @Res() res: Response) {
    // ruleid: js-xss-taint, js-xss-sink
    res.send('<p>' + value + '</p>');
  }

  // source: js-xss-taint @Body INPUT
  @Get('viaxssbody')
  async viaXssBody(@Body('k') value: string, @Res() res: Response) {
    // ruleid: js-xss-taint, js-xss-sink
    res.send('<p>' + value + '</p>');
  }

  // source: js-xss-taint @Headers INPUT
  @Get('viaxssheaders')
  async viaXssHeaders(@Headers('x-k') value: string, @Res() res: Response) {
    // ruleid: js-xss-taint, js-xss-sink
    res.send('<p>' + value + '</p>');
  }

  // source: js-xss-taint @Req INPUT
  @Get('viaxssreqr')
  async viaXssReqR(@Req() r: Request, @Res() res: Response) {
    // ruleid: js-xss-taint
    res.send('<p>' + r.query.k + '</p>');
  }

  // source: js-xss-taint @Req INPUT
  @Get('viaxssreqhttpreq')
  async viaXssReqHttpreq(@Req() httpReq: Request, @Res() res: Response) {
    // ruleid: js-xss-taint
    res.send('<p>' + httpReq.body.k + '</p>');
  }

  // source: js-ssrf-taint @Query INPUT
  @Get('viassrfquery')
  async viaSsrfQuery(@Query('k') value: string) {
    // ruleid: js-ssrf-taint
    return fetch(value);
  }

  // source: js-ssrf-taint @Param INPUT
  @Get('viassrfparam')
  async viaSsrfParam(@Param('k') value: string) {
    // ruleid: js-ssrf-taint
    return fetch(value);
  }

  // source: js-ssrf-taint @Body INPUT
  @Get('viassrfbody')
  async viaSsrfBody(@Body('k') value: string) {
    // ruleid: js-ssrf-taint
    return fetch(value);
  }

  // source: js-ssrf-taint @Headers INPUT
  @Get('viassrfheaders')
  async viaSsrfHeaders(@Headers('x-k') value: string) {
    // ruleid: js-ssrf-taint
    return fetch(value);
  }

  // source: js-ssrf-taint @Req INPUT
  @Get('viassrfreqr')
  async viaSsrfReqR(@Req() r: Request) {
    // ruleid: js-ssrf-taint
    return fetch(r.query.k);
  }

  // source: js-ssrf-taint @Req INPUT
  @Get('viassrfreqhttpreq')
  async viaSsrfReqHttpreq(@Req() httpReq: Request) {
    // ruleid: js-ssrf-taint
    return fetch(httpReq.body.k);
  }

  // source: js-path-traversal-taint @Query INPUT
  @Get('viapathtraversalquery')
  async viaPathTraversalQuery(@Query('k') value: string) {
    // ruleid: js-path-traversal-taint
    return fsp.readFile(path.join(UPLOAD_DIR, value), 'utf8');
  }

  // source: js-path-traversal-taint @Param INPUT
  @Get('viapathtraversalparam')
  async viaPathTraversalParam(@Param('k') value: string) {
    // ruleid: js-path-traversal-taint
    return fsp.readFile(path.join(UPLOAD_DIR, value), 'utf8');
  }

  // source: js-path-traversal-taint @Body INPUT
  @Get('viapathtraversalbody')
  async viaPathTraversalBody(@Body('k') value: string) {
    // ruleid: js-path-traversal-taint
    return fsp.readFile(path.join(UPLOAD_DIR, value), 'utf8');
  }

  // source: js-path-traversal-taint @Headers INPUT
  @Get('viapathtraversalheaders')
  async viaPathTraversalHeaders(@Headers('x-k') value: string) {
    // ruleid: js-path-traversal-taint
    return fsp.readFile(path.join(UPLOAD_DIR, value), 'utf8');
  }

  // source: js-path-traversal-taint @Req INPUT
  @Get('viapathtraversalreqr')
  async viaPathTraversalReqR(@Req() r: Request) {
    // ruleid: js-path-traversal-taint
    return fsp.readFile(path.join(UPLOAD_DIR, r.query.k), 'utf8');
  }

  // source: js-path-traversal-taint @Req INPUT
  @Get('viapathtraversalreqhttpreq')
  async viaPathTraversalReqHttpreq(@Req() httpReq: Request) {
    // ruleid: js-path-traversal-taint
    return fsp.readFile(path.join(UPLOAD_DIR, httpReq.body.k), 'utf8');
  }

  // source: js-open-redirect-taint @Query INPUT
  @Get('viaopenredirectquery')
  async viaOpenRedirectQuery(@Query('k') value: string, @Res() res: Response) {
    // ruleid: js-open-redirect-taint, js-open-redirect-sink
    res.redirect(value);
  }

  // source: js-open-redirect-taint @Param INPUT
  @Get('viaopenredirectparam')
  async viaOpenRedirectParam(@Param('k') value: string, @Res() res: Response) {
    // ruleid: js-open-redirect-taint, js-open-redirect-sink
    res.redirect(value);
  }

  // source: js-open-redirect-taint @Body INPUT
  @Get('viaopenredirectbody')
  async viaOpenRedirectBody(@Body('k') value: string, @Res() res: Response) {
    // ruleid: js-open-redirect-taint, js-open-redirect-sink
    res.redirect(value);
  }

  // source: js-open-redirect-taint @Headers INPUT
  @Get('viaopenredirectheaders')
  async viaOpenRedirectHeaders(@Headers('x-k') value: string, @Res() res: Response) {
    // ruleid: js-open-redirect-taint, js-open-redirect-sink
    res.redirect(value);
  }

  // source: js-open-redirect-taint @Req INPUT
  @Get('viaopenredirectreqr')
  async viaOpenRedirectReqR(@Req() r: Request, @Res() res: Response) {
    // ruleid: js-open-redirect-taint
    res.redirect(r.query.k);
  }

  // source: js-open-redirect-taint @Req INPUT
  @Get('viaopenredirectreqhttpreq')
  async viaOpenRedirectReqHttpreq(@Req() httpReq: Request, @Res() res: Response) {
    // ruleid: js-open-redirect-taint
    res.redirect(httpReq.body.k);
  }
}
