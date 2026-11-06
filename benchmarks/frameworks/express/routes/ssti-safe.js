const ejs = require('ejs');
const express = require('express');

const SAMPLE_ORDER = { customer: 'Ada Lovelace', orderId: 'A-1001', total: '$42.00' };
const ORDER_TEMPLATE = '<p>Hi <%= customer %>, order <%= orderId %> totals <%= total %>.</p>';

const router = express.Router();

router.post('/', (req, res) => {
  const customer = req.body.customer;
  const html = ejs.render(ORDER_TEMPLATE, { ...SAMPLE_ORDER, customer }); // EVAL-SAFE
  res.json({ preview: html });
});

module.exports = router;
