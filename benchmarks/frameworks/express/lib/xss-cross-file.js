function renderResults(res, q) {
  res.send(`<h1>Search results for ${q}</h1>`); // EVAL-SINK
}

module.exports = { renderResults };
