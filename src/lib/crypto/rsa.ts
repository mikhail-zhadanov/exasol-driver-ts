// Default re-export. The package.json `imports` map redirects
// `#crypto/rsa` to either rsa.node or rsa.browser depending on the
// active conditional export. This file only matters as a fallback;
// nothing in the driver imports it directly.
export { encryptPasswordPkcs1v15 } from './rsa.node';
