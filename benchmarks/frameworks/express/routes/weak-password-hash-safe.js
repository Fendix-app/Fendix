const bcrypt = require('bcrypt');
const express = require('express');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

router.post('/', async (req, res) => {
  const { email, password } = req.body;
  const passwordHash = await bcrypt.hash(password, 12); // EVAL-SAFE
  await pool.query('INSERT INTO users (email, password_hash) VALUES ($1, $2)', [email, passwordHash]);
  res.status(201).json({ email });
});

module.exports = router;
