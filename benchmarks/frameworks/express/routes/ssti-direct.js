const ejs = require('ejs');
const express = require('express');

const SAMPLE_ORDER = { customer: 'Ada Lovelace', orderId: 'A-1001', total: '$42.00' };

const router = express.Router();

router.post('/', (req, res) => {
  const template = req.body.template;
  const html = ejs.render(template, SAMPLE_ORDER); // EVAL-SINK
  res.json({ preview: html });
});

module.exports = router;
