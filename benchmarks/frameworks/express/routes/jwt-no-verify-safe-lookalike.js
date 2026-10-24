const express = require('express');
const jwt = require('jsonwebtoken');

const PUBLIC_KEYS = new Map([
  ['auth-2026-01', process.env.JWT_PUBLIC_KEY_CURRENT],
  ['auth-2025-07', process.env.JWT_PUBLIC_KEY_PREVIOUS],
]);

const router = express.Router();

router.get('/', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  const decoded = jwt.decode(token, { complete: true }); // EVAL-SAFE
  const publicKey = decoded && PUBLIC_KEYS.get(decoded.header.kid);
  if (!publicKey) {
    return res.status(401).json({ error: 'Unknown signing key' });
  }
  let claims;
  try {
    claims = jwt.verify(token, publicKey, { algorithms: ['RS256'] });
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
  if (claims.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json({ user: claims.sub, permissions: ['reports:read', 'users:write'] });
});

module.exports = router;
