// @flow
// Rule tests for rules/javascript-crypto.yaml on JavaScript that uses Flow's
// `as` cast (Flow 0.229+): the `const {..., $V, ...} = $E as $T` source of each
// taint rule, in a .js file. See javascript-injection.flow-as.js.

import bcrypt from 'bcrypt';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';

export async function register(req, res) {
  const { password } = (req.body as { password: string });
  // ruleid: js-weak-password-hash-taint, js-weak-password-hash-sink
  const passwordHash = crypto.createHash('md5').update(password).digest('hex');
  // ok: js-weak-password-hash-taint
  const strong = await bcrypt.hash(password, 12);
  res.json({ passwordHash, strong });
}

export function claims(req, res) {
  const { token } = (req.headers as { token: string });
  // ruleid: js-jwt-no-verify-taint
  const decoded = jwt.decode(token);
  res.json(decoded);
}

// Decoded to read the key id, then verified: not a finding.
export function verifiedClaims(req, res) {
  const { token } = (req.headers as { token: string });
  // ok: js-jwt-no-verify-taint
  const header = jwt.decode(token, { complete: true });
  res.json(jwt.verify(token, process.env.JWT_SECRET, { algorithms: ['HS256'], keyid: header?.header.kid }));
}
