// Rule tests for rules/javascript-crypto.yaml: every NestJS parameter
// decorator each taint rule reads as a source, one handler per (rule,
// decorator). Each handler is marked `// source: <rule> @<decorator> <label>`;
// TestJavaScriptDecoratorSourcesHaveCases (../js_mirror_test.go) requires a
// marked case for every decorator item of every rule, in this file and its
// .js mirror. No parameter is named req or request and no handler is named
// after an HTTP method, so the Express and Next.js sources cannot report
// these lines: only the decorator source can. See README.md.

import { Body, Controller, Get, Headers, Param, Query, Req } from '@nestjs/common';

import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

@Controller('crypto-decorators')
export class CryptoDecoratorSources {
  // source: js-weak-password-hash-taint @Query INPUT
  @Get('viaweakpasswordhashquery')
  async viaWeakPasswordHashQuery(@Query('k') value        ) {
    const pwd = value;
    // ruleid: js-weak-password-hash-taint, js-weak-password-hash-sink
    return crypto.createHash('md5').update(pwd).digest('hex');
  }

  // source: js-weak-password-hash-taint @Param INPUT
  @Get('viaweakpasswordhashparam')
  async viaWeakPasswordHashParam(@Param('k') value        ) {
    const pwd = value;
    // ruleid: js-weak-password-hash-taint, js-weak-password-hash-sink
    return crypto.createHash('md5').update(pwd).digest('hex');
  }

  // source: js-weak-password-hash-taint @Body INPUT
  @Get('viaweakpasswordhashbody')
  async viaWeakPasswordHashBody(@Body('k') value        ) {
    const pwd = value;
    // ruleid: js-weak-password-hash-taint, js-weak-password-hash-sink
    return crypto.createHash('md5').update(pwd).digest('hex');
  }

  // source: js-weak-password-hash-taint @Headers INPUT
  @Get('viaweakpasswordhashheaders')
  async viaWeakPasswordHashHeaders(@Headers('x-k') value        ) {
    const pwd = value;
    // ruleid: js-weak-password-hash-taint, js-weak-password-hash-sink
    return crypto.createHash('md5').update(pwd).digest('hex');
  }

  // source: js-weak-password-hash-taint @Req INPUT
  @Get('viaweakpasswordhashreqr')
  async viaWeakPasswordHashReqR(@Req() r         ) {
    const pwd = r.query.k;
    // ruleid: js-weak-password-hash-taint, js-weak-password-hash-sink
    return crypto.createHash('md5').update(pwd).digest('hex');
  }

  // source: js-weak-password-hash-taint @Req INPUT
  @Get('viaweakpasswordhashreqhttpreq')
  async viaWeakPasswordHashReqHttpreq(@Req() httpReq         ) {
    const pwd = httpReq.body.k;
    // ruleid: js-weak-password-hash-taint, js-weak-password-hash-sink
    return crypto.createHash('md5').update(pwd).digest('hex');
  }

  // source: js-weak-password-hash-taint @Body PASSWORD
  @Get('viaweakpasswordhashbodypassword')
  async viaWeakPasswordHashBodyPassword(@Body('password') secret        ) {
    // ruleid: js-weak-password-hash-taint
    return crypto.createHash('md5').update(secret).digest('hex');
  }

  // source: js-jwt-no-verify-taint @Query INPUT
  @Get('viajwtnoverifyquery')
  async viaJwtNoVerifyQuery(@Query('k') value        ) {
    // ruleid: js-jwt-no-verify-taint, js-jwt-no-verify-sink
    return jwt.decode(value);
  }

  // source: js-jwt-no-verify-taint @Param INPUT
  @Get('viajwtnoverifyparam')
  async viaJwtNoVerifyParam(@Param('k') value        ) {
    // ruleid: js-jwt-no-verify-taint, js-jwt-no-verify-sink
    return jwt.decode(value);
  }

  // source: js-jwt-no-verify-taint @Body INPUT
  @Get('viajwtnoverifybody')
  async viaJwtNoVerifyBody(@Body('k') value        ) {
    // ruleid: js-jwt-no-verify-taint, js-jwt-no-verify-sink
    return jwt.decode(value);
  }

  // source: js-jwt-no-verify-taint @Headers INPUT
  @Get('viajwtnoverifyheaders')
  async viaJwtNoVerifyHeaders(@Headers('x-k') value        ) {
    // ruleid: js-jwt-no-verify-taint, js-jwt-no-verify-sink
    return jwt.decode(value);
  }

  // source: js-jwt-no-verify-taint @Req INPUT
  @Get('viajwtnoverifyreqr')
  async viaJwtNoVerifyReqR(@Req() r         ) {
    // ruleid: js-jwt-no-verify-taint
    return jwt.decode(r.query.k);
  }

  // source: js-jwt-no-verify-taint @Req INPUT
  @Get('viajwtnoverifyreqhttpreq')
  async viaJwtNoVerifyReqHttpreq(@Req() httpReq         ) {
    // ruleid: js-jwt-no-verify-taint
    return jwt.decode(httpReq.body.k);
  }
}
