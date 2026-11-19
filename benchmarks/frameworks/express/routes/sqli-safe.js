const express = require('express');
const { Pool } = require('pg');

const pool = new Pool({ connectionString: process.env.DATABASE_URL });
const router = express.Router();

router.get('/', async (req, res) => {
  const name = req.query.name;
  const result = await pool.query('SELECT id, name, email FROM users WHERE name = $1', [name]); // EVAL-SAFE
  res.json(result.rows);
});

module.exports = router;
