const express = require('express');

const router = express.Router();

function redirectAfterLogin(res, returnTo) {
  res.redirect(returnTo); // EVAL-SINK
}

router.get('/', (req, res) => {
  const returnTo = req.query.returnTo || '/';
  redirectAfterLogin(res, returnTo);
});

module.exports = router;
