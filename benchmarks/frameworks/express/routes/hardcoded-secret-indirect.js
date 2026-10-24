const express = require('express');

const config = {
  github: {
    apiUrl: 'https://api.github.com',
    token: '__EVAL_GITHUB_TOKEN__', // EVAL-SINK
  },
};

const router = express.Router();

async function githubRequest(endpoint) {
  const response = await fetch(`${config.github.apiUrl}${endpoint}`, {
    headers: {
      Accept: 'application/vnd.github+json',
      Authorization: `Bearer ${config.github.token}`,
    },
  });
  return response.json();
}

router.get('/', async (req, res) => {
  const release = await githubRequest('/repos/acme/platform/releases/latest');
  res.json({ tag: release.tag_name, publishedAt: release.published_at });
});

module.exports = router;
