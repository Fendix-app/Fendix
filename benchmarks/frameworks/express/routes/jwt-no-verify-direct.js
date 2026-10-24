const express = require('express');
const jwt = require('jsonwebtoken');

const router = express.Router();

router.get('/', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  const claims = jwt.decode(token); // EVAL-SINK
  if (!claims || claims.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json({ user: claims.sub, permissions: ['reports:read', 'users:write'] });
});

module.exports = router;
