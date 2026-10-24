const express = require('express');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

function generateResetToken() {
  return Math.random().toString(36).slice(2) + Math.random().toString(36).slice(2); // EVAL-SINK
}

router.post('/', async (req, res) => {
  const email = req.body.email;
  const resetToken = generateResetToken();
  await pool.query("INSERT INTO password_resets (email, token, expires_at) VALUES ($1, $2, NOW() + INTERVAL '1 hour')", [email, resetToken]);
  res.status(202).json({ status: 'If the account exists, a reset link has been sent.' });
});

module.exports = router;
