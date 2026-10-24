const ejs = require('ejs');
const express = require('express');

const FOOTER_TEMPLATE = '<footer>&copy; <%= year %> Acme Inc. All rights reserved.</footer>';

const router = express.Router();

router.get('/', (req, res) => {
  const html = ejs.render(FOOTER_TEMPLATE, { year: new Date().getFullYear() }); // EVAL-SAFE
  res.json({ footer: html });
});

module.exports = router;
