const crypto = require('node:crypto');
const express = require('express');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

router.post('/', async (req, res) => {
  const { email, password } = req.body;
  const passwordHash = crypto.createHash('md5').update(password).digest('hex'); // EVAL-SINK
  await pool.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [email, passwordHash]);
  res.status(201).json({ email });
});

module.exports = router;
