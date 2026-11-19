const express = require('express');
const jwt = require('jsonwebtoken');

const JWT_SECRET = process.env.JWT_SECRET;

const router = express.Router();

router.get('/', (req, res) => {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  let claims;
  try {
    claims = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }); // EVAL-SAFE
  } catch {
    return res.status(401).json({ error: 'Invalid token' });
  }
  if (claims.role !== 'admin') {
    return res.status(403).json({ error: 'Forbidden' });
  }
  res.json({ user: claims.sub, permissions: ['reports:read', 'users:write'] });
});

module.exports = router;
