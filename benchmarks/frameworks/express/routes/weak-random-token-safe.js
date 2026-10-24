const crypto = require('node:crypto');
const express = require('express');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

router.post('/', async (req, res) => {
  const email = req.body.email;
  const resetToken = crypto.randomBytes(32).toString('hex'); // EVAL-SAFE
  await pool.query("INSERT INTO password_resets (email, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')", [email, resetToken]);
  res.status(202).json({ status: 'If the account exists, a reset link has been sent.' });
});

module.exports = router;
