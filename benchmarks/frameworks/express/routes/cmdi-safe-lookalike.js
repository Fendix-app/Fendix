const express = require('express');
const { exec } = require('node:child_process');
const { promisify } = require('node:util');

const LOG_DIR = '/var/log/app';

const execAsync = promisify(exec);
const router = express.Router();

router.get('/', async (req, res) => {
  const { stdout } = await execAsync(`du -sh ${LOG_DIR}`); // EVAL-SAFE
  res.json({ usage: stdout.trim() });
});

module.exports = router;
