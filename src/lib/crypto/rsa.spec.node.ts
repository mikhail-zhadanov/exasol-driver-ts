import { constants as cryptoConstants, generateKeyPairSync, privateDecrypt } from 'node:crypto';
import { encryptPasswordPkcs1v15 } from './rsa.node';

// Pin down the RSA-PKCS1-v1.5 behaviour of the node entry. We round-trip
// the driver helper through a freshly generated keypair and assert
// byte-for-byte equality. Cases mirror the ones in the consumer's
// vscode-extension test suite that motivated the dual-entry split.

describe('encryptPasswordPkcs1v15 (node entry)', () => {
  it('round-trips a plain ASCII password', () => {
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' }) as { n: string; e: string };
    const modulusHex = Buffer.from(jwk.n, 'base64url').toString('hex');
    const exponentHex = Buffer.from(jwk.e, 'base64url').toString('hex');

    const password = 'correct horse battery staple';
    const ciphertextBase64 = encryptPasswordPkcs1v15(password, modulusHex, exponentHex);

    const plaintext = privateDecrypt(
      { key: privateKey, padding: cryptoConstants.RSA_PKCS1_PADDING },
      Buffer.from(ciphertextBase64, 'base64'),
    ).toString('binary');

    expect(plaintext).toEqual(password);
  });

  it('pads odd-length modulus/exponent hex rather than silently truncating', () => {
    // Buffer.from(hex) drops a trailing nibble on odd-length input. The
    // helper pads to even length to match forge's BigInteger semantics.
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' }) as { n: string; e: string };
    const modulusHex = Buffer.from(jwk.n, 'base64url').toString('hex').replace(/^0/, '');
    const exponentHex = Buffer.from(jwk.e, 'base64url').toString('hex');

    const password = 'odd-length-test';
    const ciphertextBase64 = encryptPasswordPkcs1v15(password, modulusHex, exponentHex);

    const plaintext = privateDecrypt(
      { key: privateKey, padding: cryptoConstants.RSA_PKCS1_PADDING },
      Buffer.from(ciphertextBase64, 'base64'),
    ).toString('binary');

    expect(plaintext).toEqual(password);
  });

  it('encodes the password as binary (1 byte per char code), preserving high-bit bytes', () => {
    // forge.pubKey.encrypt(jsString) treated the string as a binary
    // string, one byte per UTF-16 code unit (low byte). We must match
    // that to avoid breaking existing users whose passwords have bytes
    // above 0x7f.
    const { publicKey, privateKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' }) as { n: string; e: string };
    const modulusHex = Buffer.from(jwk.n, 'base64url').toString('hex');
    const exponentHex = Buffer.from(jwk.e, 'base64url').toString('hex');

    const password = 'p©ssword'; // 0xa9 = copyright sign
    const ciphertextBase64 = encryptPasswordPkcs1v15(password, modulusHex, exponentHex);

    const plaintextBinary = privateDecrypt(
      { key: privateKey, padding: cryptoConstants.RSA_PKCS1_PADDING },
      Buffer.from(ciphertextBase64, 'base64'),
    ).toString('binary');

    expect(plaintextBinary).toEqual(password);
    expect(Buffer.from(password, 'binary').length).toEqual(8);
    expect(Buffer.from(password, 'utf8').length).toEqual(9);
  });

  it('returns valid base64 of full modulus byte length (256 for 2048-bit key)', () => {
    const { publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048 });
    const jwk = publicKey.export({ format: 'jwk' }) as { n: string; e: string };
    const modulusHex = Buffer.from(jwk.n, 'base64url').toString('hex');
    const exponentHex = Buffer.from(jwk.e, 'base64url').toString('hex');

    const ciphertextBase64 = encryptPasswordPkcs1v15('x', modulusHex, exponentHex);
    expect(/^[A-Za-z0-9+/]+={0,2}$/.test(ciphertextBase64)).toEqual(true);
    expect(Buffer.from(ciphertextBase64, 'base64').length).toEqual(256);
  });
});
