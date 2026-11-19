const crypto = require('node:crypto');
const express = require('express');

const PLANS = [
  { id: 'free', priceCents: 0 },
  { id: 'team', priceCents: 2000 },
  { id: 'enterprise', priceCents: 9900 },
];

const router = express.Router();

router.get('/', (req, res) => {
  const body = JSON.stringify(PLANS);
  const etag = crypto.createHash('md5').update(body).digest('hex'); // EVAL-SAFE
  res.set('ETag', `"${etag}"`);
  res.type('application/json').send(body);
});

module.exports = router;
