import JSEncrypt from 'jsencrypt';

// Minimal browser-global declarations so this file typechecks without
// pulling DOM lib into the project-wide tsconfig.
declare const btoa: (s: string) => string;
declare const crypto: { getRandomValues: (buf: Uint8Array) => Uint8Array };

// Browser entry point for the login RSA-PKCS1-v1.5 path.
//
// Background: the Web Crypto API does not implement RSAES-PKCS1-v1.5
// (the Exasol login wire format), only RSA-OAEP. We use jsencrypt to
// provide PKCS#1 v1.5 in browsers. To match the node entry's behaviour
// byte-for-byte, two things matter:
//
//   1. The password must be encoded as a binary string (1 byte per char
//      code, low byte only). jsencrypt's default JSEncrypt.encrypt()
//      UTF-8-encodes multi-byte chars via pkcs1pad2, which would diverge
//      from forge / node:crypto for non-ASCII bytes. We therefore drop
//      into the underlying RSAKey.encrypt() with a custom padding
//      function that interprets the input as raw bytes.
//
//   2. jsencrypt accepts public keys as PEM (SPKI). The driver receives
//      a raw modulus/exponent hex pair, so we hand-build a minimal
//      SubjectPublicKeyInfo DER and base64-wrap it as PEM.
//
// The result (an even-length hex string from RSAKey.encrypt) is
// converted to base64 to match the node entry's return contract.

const padHex = (hex: string): string => (hex.length % 2 === 0 ? hex : '0' + hex);

// Encode a non-negative integer as a DER length (short or long form).
function derLength(n: number): number[] {
  if (n < 0x80) return [n];
  const bytes: number[] = [];
  let v = n;
  while (v > 0) {
    bytes.unshift(v & 0xff);
    v >>= 8;
  }
  return [0x80 | bytes.length, ...bytes];
}

// Encode an unsigned big-endian integer (hex) as an ASN.1 INTEGER. DER
// requires a leading 0x00 byte when the high bit of the first content
// byte is set, to keep it positive.
function derInteger(hex: string): number[] {
  const padded = padHex(hex);
  const bytes: number[] = [];
  for (let i = 0; i < padded.length; i += 2) {
    bytes.push(parseInt(padded.slice(i, i + 2), 16));
  }
  if (bytes.length > 0 && (bytes[0] & 0x80) !== 0) {
    bytes.unshift(0x00);
  }
  return [0x02, ...derLength(bytes.length), ...bytes];
}

function derSequence(...children: number[][]): number[] {
  const body = ([] as number[]).concat(...children);
  return [0x30, ...derLength(body.length), ...body];
}

function derBitString(content: number[]): number[] {
  const body = [0x00, ...content]; // 0 unused bits
  return [0x03, ...derLength(body.length), ...body];
}

// OID 1.2.840.113549.1.1.1 (rsaEncryption), DER-encoded as an OID value.
const RSA_ENCRYPTION_OID: number[] = [
  0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];
const ASN1_NULL: number[] = [0x05, 0x00];

function bytesToBase64(bytes: number[]): string {
  let s = '';
  for (let i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
  // btoa is available in browsers and jsdom; this module never runs in Node.
  return btoa(s);
}

function buildSpkiPem(modulusHex: string, exponentHex: string): string {
  // SubjectPublicKeyInfo ::= SEQUENCE {
  //   algorithm   AlgorithmIdentifier ::= SEQUENCE { OID rsaEncryption, NULL },
  //   PublicKey   BIT STRING { SEQUENCE { INTEGER modulus, INTEGER exponent } }
  // }
  const algId = derSequence(RSA_ENCRYPTION_OID, ASN1_NULL);
  const rsaPub = derSequence(derInteger(modulusHex), derInteger(exponentHex));
  const spki = derSequence(algId, derBitString(rsaPub));
  const b64 = bytesToBase64(spki);
  // 64-char line wrap per RFC 7468.
  const wrapped = b64.replace(/(.{64})/g, '$1\n');
  return `-----BEGIN PUBLIC KEY-----\n${wrapped}\n-----END PUBLIC KEY-----`;
}

// Custom PKCS#1 v1.5 type-2 padding that treats the input string as raw
// bytes (1 byte per char code, low byte only). Mirrors node:crypto's
// Buffer.from(password, 'binary') interpretation.
//
// Returns a value suitable for RSAKey.doPublic, constructed via the
// same BigInteger class the loaded key uses (reached through the key
// instance to avoid depending on jsencrypt's private subpaths).
function makeBinaryPkcs1Padder(BigIntegerCtor: new (a: number[]) => unknown) {
  return (s: string, n: number): unknown => {
    if (n < s.length + 11) {
      throw new Error('Message too long for RSA');
    }
    const ba: number[] = new Array(n);
    // Place message bytes at the tail.
    for (let i = 0; i < s.length; i++) {
      ba[n - s.length + i] = s.charCodeAt(i) & 0xff;
    }
    // Mandatory 0x00 separator before the message.
    ba[n - s.length - 1] = 0x00;
    // PS: non-zero random bytes filling positions 2..n-msg-2.
    // crypto.getRandomValues is in the WebCrypto spec, available in
    // browsers and jsdom.
    const psLen = n - s.length - 3;
    const psBytes = new Uint8Array(psLen);
    crypto.getRandomValues(psBytes);
    for (let i = 0; i < psLen; i++) {
      let b = psBytes[i];
      while (b === 0) {
        const one = new Uint8Array(1);
        crypto.getRandomValues(one);
        b = one[0];
      }
      ba[2 + i] = b;
    }
    // Block type 2 header.
    ba[0] = 0x00;
    ba[1] = 0x02;
    return new BigIntegerCtor(ba);
  };
}

function hexToBase64(hex: string): string {
  const bytes: number[] = [];
  for (let i = 0; i < hex.length; i += 2) {
    bytes.push(parseInt(hex.slice(i, i + 2), 16));
  }
  return bytesToBase64(bytes);
}

export function encryptPasswordPkcs1v15(
  password: string,
  publicKeyModulusHex: string,
  publicKeyExponentHex: string,
): string {
  const pem = buildSpkiPem(publicKeyModulusHex, publicKeyExponentHex);
  const jse = new JSEncrypt();
  jse.setPublicKey(pem);
  // getKey() returns the underlying JSEncryptRSAKey, which extends
  // jsencrypt's RSAKey. Cast through unknown because jsencrypt does
  // not export the BigInteger or RSAKey types from its public surface.
  const rsaKey = jse.getKey() as unknown as {
    n: { constructor: new (a: number[]) => unknown };
    encrypt: (text: string, paddingFunction: (s: string, n: number) => unknown) => string;
  };
  const BigIntegerCtor = rsaKey.n.constructor;
  const padder = makeBinaryPkcs1Padder(BigIntegerCtor);
  const hex = rsaKey.encrypt(password, padder as (s: string, n: number) => unknown);
  if (!hex) {
    throw new Error('RSA encryption failed');
  }
  return hexToBase64(hex);
}
