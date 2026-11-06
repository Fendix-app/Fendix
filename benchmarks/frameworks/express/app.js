const express = require('express');

const app = express();
app.use(express.json());

app.use('/api/sqli-direct', require('./routes/sqli-direct'));
app.use('/api/sqli-indirect', require('./routes/sqli-indirect'));
app.use('/api/sqli-safe', require('./routes/sqli-safe'));
app.use('/api/sqli-safe-lookalike', require('./routes/sqli-safe-lookalike'));

app.use('/api/cmdi-direct', require('./routes/cmdi-direct'));
app.use('/api/cmdi-indirect', require('./routes/cmdi-indirect'));
app.use('/api/cmdi-safe', require('./routes/cmdi-safe'));
app.use('/api/cmdi-safe-lookalike', require('./routes/cmdi-safe-lookalike'));

app.use('/api/xss-direct', require('./routes/xss-direct'));
app.use('/api/xss-indirect', require('./routes/xss-indirect'));
app.use('/api/xss-safe', require('./routes/xss-safe'));
app.use('/api/xss-safe-lookalike', require('./routes/xss-safe-lookalike'));

app.use('/api/ssrf-direct', require('./routes/ssrf-direct'));
app.use('/api/ssrf-indirect', require('./routes/ssrf-indirect'));
app.use('/api/ssrf-safe', require('./routes/ssrf-safe'));
app.use('/api/ssrf-safe-lookalike', require('./routes/ssrf-safe-lookalike'));

app.use('/api/path-traversal-direct', require('./routes/path-traversal-direct'));
app.use('/api/path-traversal-indirect', require('./routes/path-traversal-indirect'));
app.use('/api/path-traversal-safe', require('./routes/path-traversal-safe'));
app.use('/api/path-traversal-safe-lookalike', require('./routes/path-traversal-safe-lookalike'));

app.use('/api/open-redirect-direct', require('./routes/open-redirect-direct'));
app.use('/api/open-redirect-indirect', require('./routes/open-redirect-indirect'));
app.use('/api/open-redirect-safe', require('./routes/open-redirect-safe'));
app.use('/api/open-redirect-safe-lookalike', require('./routes/open-redirect-safe-lookalike'));

app.use('/api/hardcoded-secret-direct', require('./routes/hardcoded-secret-direct'));
app.use('/api/hardcoded-secret-indirect', require('./routes/hardcoded-secret-indirect'));
app.use('/api/hardcoded-secret-safe', require('./routes/hardcoded-secret-safe'));
app.use('/api/hardcoded-secret-safe-lookalike', require('./routes/hardcoded-secret-safe-lookalike'));

app.use('/api/weak-password-hash-direct', require('./routes/weak-password-hash-direct'));
app.use('/api/weak-password-hash-indirect', require('./routes/weak-password-hash-indirect'));
app.use('/api/weak-password-hash-safe', require('./routes/weak-password-hash-safe'));
app.use('/api/weak-password-hash-safe-lookalike', require('./routes/weak-password-hash-safe-lookalike'));

app.use('/api/jwt-no-verify-direct', require('./routes/jwt-no-verify-direct'));
app.use('/api/jwt-no-verify-indirect', require('./routes/jwt-no-verify-indirect'));
app.use('/api/jwt-no-verify-safe', require('./routes/jwt-no-verify-safe'));
app.use('/api/jwt-no-verify-safe-lookalike', require('./routes/jwt-no-verify-safe-lookalike'));

app.use('/api/weak-random-token-direct', require('./routes/weak-random-token-direct'));
app.use('/api/weak-random-token-indirect', require('./routes/weak-random-token-indirect'));
app.use('/api/weak-random-token-safe', require('./routes/weak-random-token-safe'));
app.use('/api/weak-random-token-safe-lookalike', require('./routes/weak-random-token-safe-lookalike'));

app.use('/api/ssti-direct', require('./routes/ssti-direct'));
app.use('/api/ssti-indirect', require('./routes/ssti-indirect'));
app.use('/api/ssti-safe', require('./routes/ssti-safe'));
app.use('/api/ssti-safe-lookalike', require('./routes/ssti-safe-lookalike'));

app.use('/api/sqli-cross-file', require('./routes/sqli-cross-file'));
app.use('/api/sqli-alt-api', require('./routes/sqli-alt-api'));
app.use('/api/cmdi-cross-file', require('./routes/cmdi-cross-file'));
app.use('/api/cmdi-alt-api', require('./routes/cmdi-alt-api'));
app.use('/api/xss-cross-file', require('./routes/xss-cross-file'));
app.use('/api/xss-alt-api', require('./routes/xss-alt-api'));
app.use('/api/ssrf-cross-file', require('./routes/ssrf-cross-file'));
app.use('/api/ssrf-alt-api', require('./routes/ssrf-alt-api'));
app.use('/api/path-traversal-cross-file', require('./routes/path-traversal-cross-file'));
app.use('/api/path-traversal-alt-api', require('./routes/path-traversal-alt-api'));
app.use('/api/open-redirect-cross-file', require('./routes/open-redirect-cross-file'));
app.use('/api/open-redirect-alt-api', require('./routes/open-redirect-alt-api'));
app.use('/api/hardcoded-secret-cross-file', require('./routes/hardcoded-secret-cross-file'));
app.use('/api/hardcoded-secret-alt-api', require('./routes/hardcoded-secret-alt-api'));

const port = Number(process.env.PORT) || 3000;
app.listen(port, () => {
  console.log(`Listening on port ${port}`);
});

module.exports = app;
