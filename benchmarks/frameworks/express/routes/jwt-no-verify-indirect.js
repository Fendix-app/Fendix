const express = require('express');
const jwt = require('jsonwebtoken');

const router = express.Router();

function getClaims(token) {
  return jwt.decode(token); // EVAL-SINK
}

router.get('/', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  const claims = getClaims(token);
  if (!claims || claims.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json({ user: claims.sub, permissions: ['reports:read', 'users:write'] });
});

module.exports = router;
