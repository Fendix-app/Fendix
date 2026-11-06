const express = require('express');

const LOGIN_URL = 'https://accounts.example.com/login';

const router = express.Router();

router.get('/', (req, res) => {
  res.clearCookie('session');
  res.redirect(LOGIN_URL); // EVAL-SAFE
});

module.exports = router;
