// Control: run without the gofips OPENSSL_CONF. MD5 must work here, so
// the gofips run's MD5 failure shows exclusion, not missing support.
const crypto = require('node:crypto');
let ok = true;
try {
  const d = crypto.createHash('md5').update('abc').digest('hex');
  console.log((d === '900150983cd24fb0d6963f7d28e17f72' ? 'PASS: ' : 'FAIL: ') + 'control: md5(abc) == 90015098... (default provider active)');
  ok = d === '900150983cd24fb0d6963f7d28e17f72';
} catch (e) {
  console.log('FAIL: control: md5 threw with default provider active: ' + e.message);
  ok = false;
}
console.log(ok ? 'CONTROL PASSED' : 'CONTROL FAILED');
process.exit(ok ? 0 : 1);
