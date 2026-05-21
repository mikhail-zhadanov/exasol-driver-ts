import { constants as cryptoConstants, createPublicKey, publicEncrypt } from 'node:crypto';

// Node entry point for the login RSA-PKCS1-v1.5 path.
//
// The Exasol server returns the public key as a pair of hex strings
// (modulus and exponent). We build an RSA public key via the JWK form,
// then encrypt the password under RSAES-PKCS1-v1.5 and base64-encode
// the ciphertext.
//
// Two subtleties worth preserving byte-for-byte against the historical
// node-forge implementation:
//   1. Odd-length hex inputs are left-padded with a single '0' nibble.
//      Buffer.from(hex) would otherwise silently drop a trailing nibble.
//   2. The password is encoded as a binary string (1 byte per char code,
//      low byte only). This matches forge's pubKey.encrypt(jsString) and
//      avoids breaking existing users whose passwords contain high-bit
//      bytes that would otherwise be UTF-8 expanded.

const padHex = (hex: string): string => (hex.length % 2 === 0 ? hex : '0' + hex);

export function encryptPasswordPkcs1v15(
  password: string,
  publicKeyModulusHex: string,
  publicKeyExponentHex: string,
): string {
  const modulus = Buffer.from(padHex(publicKeyModulusHex), 'hex');
  const exponent = Buffer.from(padHex(publicKeyExponentHex), 'hex');
  const pubKey = createPublicKey({
    key: {
      kty: 'RSA',
      n: modulus.toString('base64url'),
      e: exponent.toString('base64url'),
    },
    format: 'jwk',
  });
  const ciphertext = publicEncrypt(
    { key: pubKey, padding: cryptoConstants.RSA_PKCS1_PADDING },
    Buffer.from(password, 'binary'),
  );
  return ciphertext.toString('base64');
}
