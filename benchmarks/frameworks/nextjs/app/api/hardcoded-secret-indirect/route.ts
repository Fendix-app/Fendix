import { NextResponse } from 'next/server';

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

export async function GET() {
  const release = await githubRequest('/repos/acme/platform/releases/latest');
  return NextResponse.json({ tag: release.tag_name, publishedAt: release.published_at });
}
