const express = require('express');

const FEATURED_ARTICLES = ['getting-started', 'billing', 'api-keys', 'webhooks', 'single-sign-on'];

const router = express.Router();

router.get('/', (req, res) => {
  const picks = [...FEATURED_ARTICLES].sort(() => Math.random() - 0.5).slice(0, 3); // EVAL-SAFE
  res.json({ featured: picks });
});

module.exports = router;
