import { Module } from '@nestjs/common';
import { CmdiDirectController } from './controllers/cmdi-direct.controller';
import { CmdiIndirectController } from './controllers/cmdi-indirect.controller';
import { CmdiSafeLookalikeController } from './controllers/cmdi-safe-lookalike.controller';
import { CmdiSafeController } from './controllers/cmdi-safe.controller';
import { HardcodedSecretDirectController } from './controllers/hardcoded-secret-direct.controller';
import { HardcodedSecretIndirectController } from './controllers/hardcoded-secret-indirect.controller';
import { HardcodedSecretSafeLookalikeController } from './controllers/hardcoded-secret-safe-lookalike.controller';
import { HardcodedSecretSafeController } from './controllers/hardcoded-secret-safe.controller';
import { OpenRedirectDirectController } from './controllers/open-redirect-direct.controller';
import { OpenRedirectIndirectController } from './controllers/open-redirect-indirect.controller';
import { OpenRedirectSafeLookalikeController } from './controllers/open-redirect-safe-lookalike.controller';
import { OpenRedirectSafeController } from './controllers/open-redirect-safe.controller';
import { PathTraversalDirectController } from './controllers/path-traversal-direct.controller';
import { PathTraversalIndirectController } from './controllers/path-traversal-indirect.controller';
import { PathTraversalSafeLookalikeController } from './controllers/path-traversal-safe-lookalike.controller';
import { PathTraversalSafeController } from './controllers/path-traversal-safe.controller';
import { SqliDirectController } from './controllers/sqli-direct.controller';
import { SqliIndirectController } from './controllers/sqli-indirect.controller';
import { SqliSafeLookalikeController } from './controllers/sqli-safe-lookalike.controller';
import { SqliSafeController } from './controllers/sqli-safe.controller';
import { SsrfDirectController } from './controllers/ssrf-direct.controller';
import { SsrfIndirectController } from './controllers/ssrf-indirect.controller';
import { SsrfSafeLookalikeController } from './controllers/ssrf-safe-lookalike.controller';
import { SsrfSafeController } from './controllers/ssrf-safe.controller';
import { XssDirectController } from './controllers/xss-direct.controller';
import { XssIndirectController } from './controllers/xss-indirect.controller';
import { XssSafeLookalikeController } from './controllers/xss-safe-lookalike.controller';
import { XssSafeController } from './controllers/xss-safe.controller';
import { CmdiAltApiController } from './controllers/cmdi-alt-api.controller';
import { CmdiCrossFileController } from './controllers/cmdi-cross-file.controller';
import { HardcodedSecretAltApiController } from './controllers/hardcoded-secret-alt-api.controller';
import { HardcodedSecretCrossFileController } from './controllers/hardcoded-secret-cross-file.controller';
import { JwtNoVerifyDirectController } from './controllers/jwt-no-verify-direct.controller';
import { JwtNoVerifyIndirectController } from './controllers/jwt-no-verify-indirect.controller';
import { JwtNoVerifySafeLookalikeController } from './controllers/jwt-no-verify-safe-lookalike.controller';
import { JwtNoVerifySafeController } from './controllers/jwt-no-verify-safe.controller';
import { OpenRedirectAltApiController } from './controllers/open-redirect-alt-api.controller';
import { OpenRedirectCrossFileController } from './controllers/open-redirect-cross-file.controller';
import { PathTraversalAltApiController } from './controllers/path-traversal-alt-api.controller';
import { PathTraversalCrossFileController } from './controllers/path-traversal-cross-file.controller';
import { SqliAltApiController } from './controllers/sqli-alt-api.controller';
import { SqliCrossFileController } from './controllers/sqli-cross-file.controller';
import { SsrfAltApiController } from './controllers/ssrf-alt-api.controller';
import { SsrfCrossFileController } from './controllers/ssrf-cross-file.controller';
import { SstiDirectController } from './controllers/ssti-direct.controller';
import { SstiIndirectController } from './controllers/ssti-indirect.controller';
import { SstiSafeLookalikeController } from './controllers/ssti-safe-lookalike.controller';
import { SstiSafeController } from './controllers/ssti-safe.controller';
import { WeakPasswordHashDirectController } from './controllers/weak-password-hash-direct.controller';
import { WeakPasswordHashIndirectController } from './controllers/weak-password-hash-indirect.controller';
import { WeakPasswordHashSafeLookalikeController } from './controllers/weak-password-hash-safe-lookalike.controller';
import { WeakPasswordHashSafeController } from './controllers/weak-password-hash-safe.controller';
import { WeakRandomTokenDirectController } from './controllers/weak-random-token-direct.controller';
import { WeakRandomTokenIndirectController } from './controllers/weak-random-token-indirect.controller';
import { WeakRandomTokenSafeLookalikeController } from './controllers/weak-random-token-safe-lookalike.controller';
import { WeakRandomTokenSafeController } from './controllers/weak-random-token-safe.controller';
import { XssAltApiController } from './controllers/xss-alt-api.controller';
import { XssCrossFileController } from './controllers/xss-cross-file.controller';

@Module({
  controllers: [
    SqliDirectController,
    SqliIndirectController,
    SqliSafeController,
    SqliSafeLookalikeController,
    CmdiDirectController,
    CmdiIndirectController,
    CmdiSafeController,
    CmdiSafeLookalikeController,
    XssDirectController,
    XssIndirectController,
    XssSafeController,
    XssSafeLookalikeController,
    SsrfDirectController,
    SsrfIndirectController,
    SsrfSafeController,
    SsrfSafeLookalikeController,
    PathTraversalDirectController,
    PathTraversalIndirectController,
    PathTraversalSafeController,
    PathTraversalSafeLookalikeController,
    OpenRedirectDirectController,
    OpenRedirectIndirectController,
    OpenRedirectSafeController,
    OpenRedirectSafeLookalikeController,
    HardcodedSecretDirectController,
    HardcodedSecretIndirectController,
    HardcodedSecretSafeController,
    HardcodedSecretSafeLookalikeController,
    WeakPasswordHashDirectController,
    WeakPasswordHashIndirectController,
    WeakPasswordHashSafeController,
    WeakPasswordHashSafeLookalikeController,
    JwtNoVerifyDirectController,
    JwtNoVerifyIndirectController,
    JwtNoVerifySafeController,
    JwtNoVerifySafeLookalikeController,
    WeakRandomTokenDirectController,
    WeakRandomTokenIndirectController,
    WeakRandomTokenSafeController,
    WeakRandomTokenSafeLookalikeController,
    SstiDirectController,
    SstiIndirectController,
    SstiSafeController,
    SstiSafeLookalikeController,
    SqliCrossFileController,
    SqliAltApiController,
    CmdiCrossFileController,
    CmdiAltApiController,
    XssCrossFileController,
    XssAltApiController,
    SsrfCrossFileController,
    SsrfAltApiController,
    PathTraversalCrossFileController,
    PathTraversalAltApiController,
    OpenRedirectCrossFileController,
    OpenRedirectAltApiController,
    HardcodedSecretCrossFileController,
    HardcodedSecretAltApiController,
  ],
})
export class AppModule {}
