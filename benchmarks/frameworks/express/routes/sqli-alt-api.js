const express = require('express');
const mysql = require('mysql2/promise');

const pool = mysql.createPool({ uri: process.env.DATABASE_URL });
const router = express.Router();

router.get('/', async (req, res) => {
  const name = req.query.name;
  const [rows] = await pool.query("SELECT id, name, email FROM users WHERE name = '" + name + "'"); // EVAL-SINK
  res.json(rows);
});

module.exports = router;
