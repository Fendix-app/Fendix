import { Controller, Get } from '@nestjs/common';

const config = {
  github: {
    apiUrl: 'https://api.github.com',
    token: '__EVAL_GITHUB_TOKEN__', // EVAL-SINK
  },
};

async function githubRequest(endpoint: string) {
  const response = await fetch(`${config.github.apiUrl}${endpoint}`, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${config.github.token}`,
    },
  });
  return response.json();
}

@Controller('api/hardcoded-secret-indirect')
export class HardcodedSecretIndirectController {
  @Get()
  async latestRelease() {
    const release = await githubRequest('/repos/acme/platform/releases/latest');
    return { tag: release.tag_name, publishedAt: release.published_at };
  }
}
