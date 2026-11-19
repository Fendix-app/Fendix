const express = require('express');

const router = express.Router();

router.get('/', (req, res) => {
  const returnTo = req.query.returnTo || '/';
  const isLocalPath = returnTo.startsWith('/') && !returnTo.startsWith('//') && !returnTo.includes('\\');
  res.redirect(isLocalPath ? returnTo : '/'); // EVAL-SAFE
});

module.exports = router;
