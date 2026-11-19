const express = require('express');
const { findUsersByName } = require('../lib/sqli-cross-file');

const router = express.Router();

router.get('/', async (req, res) => {
  const name = req.query.name;
  const users = await findUsersByName(name);
  res.json(users);
});

module.exports = router;
