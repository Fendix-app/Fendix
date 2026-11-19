const ejs = require('ejs');
const express = require('express');

const SAMPLE_ORDER = { customer: 'Ada Lovelace', orderId: 'A-1001', total: '$42.00' };

const router = express.Router();

function renderPreview(template) {
  return ejs.render(template, SAMPLE_ORDER); // EVAL-SINK
}

router.post('/', (req, res) => {
  const template = req.body.template;
  const html = renderPreview(template);
  res.json({ preview: html });
});

module.exports = router;
