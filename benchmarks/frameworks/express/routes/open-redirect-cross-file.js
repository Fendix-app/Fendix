const express = require('express');
const { redirectAfterLogin } = require('../lib/open-redirect-cross-file');

const router = express.Router();

router.get('/', (req, res) => {
  const returnTo = req.query.returnTo || '/';
  redirectAfterLogin(res, returnTo);
});

module.exports = router;
