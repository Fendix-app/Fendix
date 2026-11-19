import { Controller, Get } from '@nestjs/common';

const FEATURED_ARTICLES = ['getting-started', 'billing', 'api-keys', 'webhooks', 'single-sign-on'];

@Controller('api/weak-random-token-safe-lookalike')
export class WeakRandomTokenSafeLookalikeController {
  @Get()
  featured() {
    const picks = [...FEATURED_ARTICLES].sort(() => Math.random() - 0.5).slice(0, 3); // EVAL-SAFE
    return { featured: picks };
  }
}
