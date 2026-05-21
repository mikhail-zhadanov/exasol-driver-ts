/**
 * @jest-environment jsdom
 */
import { constants as cryptoConstants, createPrivateKey, privateDecrypt } from 'node:crypto';
import { encryptPasswordPkcs1v15 } from './rsa.browser';

// Static 2048-bit RSA keypair used only for these tests. Generated once
// via Node so the same fixture decrypts whatever the browser path emits.
// We never generate keys inside the browser tests themselves because
// keygen in jsdom would be slow and add no value.

const MODULUS_HEX =
  'bc51bb1f6eeb1ec3073952dd27a2ae31e669cbd72d632e0f5467cc27e46e7efd3ba46c2ccbfc1564f00c562f2529a77b07fccf4cd443eb363605d96a79b79c9ae614efec79eb7a24838de3c9a8cb668fda4884d8a1cdba8084c75979b2cb61ce65344d4151d9e7095170f459a922fa6e216f1e36822295e420db1ba15f0d157f644181d58813217037778cb361683429536be9b4c927d4ac3dbd74c6791bcb29b8cc6bcec5ee8e81a6b803788fbd4b9264eda7c337fc79f1be017b5cd5762515691f59fa225c60b03c9fa1167a9300d0d644a7f80e136f0b6e09c271c536073a9995d190566d616a69e8dad728f0345432b191d054a5b9049c59a599c5e3b291';

const EXPONENT_HEX = '010001';

const PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC8Ubsfbusewwc5
Ut0noq4x5mnL1y1jLg9UZ8wn5G5+/TukbCzL/BVk8AxWLyUpp3sH/M9M1EPrNjYF
2Wp5t5ya5hTv7HnreiSDjePJqMtmj9pIhNihzbqAhMdZebLLYc5lNE1BUdnnCVFw
9FmpIvpuIW8eNoIileQg2xuhXw0Vf2RBgdWIEyFwN3eMs2FoNClTa+m0ySfUrD29
dMZ5G8spuMxrzsXujoGmuAN4j71LkmTtp8M3/HnxvgF7XNV2JRVpH1n6IlxgsDyf
oRZ6kwDQ1kSn+A4TbwtuCcJxxTYHOpmV0ZBWbWFqaeja1yjwNFQysZHQVKW5BJxZ
pZnF47KRAgMBAAECggEAEozrhaZnt01HYCRzQBUEm0pC+C8vW6J9JJef8vsLzmsU
DbeRNxvTILELyg6VVtPWaPxEkGElep1Jt4xJ8oj9fn21KMgu310WDTZ0Lph3xtfb
TQL3EwNAwKmzuHLmQ6YUDoCXLpzJPfq7QMj1LxXQvPoCp+N/MLh6syjaQSxrjccm
OkdIXvbyVIrk9ko3snEeLU+Yb07e7Tv1ASoUUKRH+HbRw4QUaWQ9ZI7G3RyQCwat
Dix2sWiLqvpsI+1hh+hokNrjyXO6pXEpxYb7l2G8x9T0Ka8ut7XsDqLgHIMI1Dij
Sgi+ZJchLnhBVBRVK77zMPZjrPZOiem4k/HEjI3JpQKBgQDiTt7uCwmlSV7zfClx
+XmWfCbOdtOSgtbvNoeMiVlQFvrtYpf2as/oveZgYtngcTMPdzWtRvPRuCVzgUmg
G+wv5INRpevE0zwwT4sRcw/NM2ZbYSA4hvo3x56Tuck3f+0qqV589zRfKl6RN4Fe
cdT9oSeXv2ctA55KCDvlPOfEJQKBgQDVBujKHUnVKCfGeAKiaDkOmwsuYRI7+9Ex
anECWhbwxzAvsy4HrTKGrSbgrsUiLPRLAn6zfoWTb2TH5fglVJf9QC/yyHCumtqs
8in7JBISEwsW9pagSXHK38qmpgPaJ7do46orLmMe/uyRh8TQWXgTP5l57aLAmoDr
k42NnwdS/QKBgQCcb/bsyFZ/mmt3ltGzhsfE/cd5m2x/b9CSBbjHrj49/dSxeiEf
5xAXjAYPhOWln7qzKy3AvTZYN5oz8SBq/EJVjPo126NSKM8HekTg6A/5Qlm0Ozyh
trSLEIOPDLOKmPTiM7gsXFoomspKSfs0xS19sgQDgv0YgdLOzEhTG7n+vQKBgQCG
/vDonDTcsqy6FfU9bCS0P8aPJo7CmmrQEO76mZKuFNxRbg/+Z2B8fiAEBF0CslBB
dJxMLSKC8vV/xBlDtt72awW3qhPWYmWvcWrvLsWQ1KaTb8K2YrSM5tLqVoxcZAzT
mGqPIL9Jtiy+cLZlfj0cnZIp9VDNE1wdbY0nsR6YFQKBgF85kIRVP5qH1iQZ4jeq
4EYwMmXST0tAVhFpz+JhRl0TWaLvQso5jHE0wtxVk1s+NdVvwqkfHNVQs1MVFkSg
DcKomi8Gk1XRcDkFQx7dKJhysUY++hv9XUSudVsbBNBH1O1vNGf1H7L6XtSSG3ZS
kxheT9fvHbKxBt4nCgHpSUFj
-----END PRIVATE KEY-----`;

function decryptWithFixture(ciphertextBase64: string): string {
  const key = createPrivateKey(PRIVATE_KEY_PEM);
  const plaintext = privateDecrypt(
    { key, padding: cryptoConstants.RSA_PKCS1_PADDING },
    Buffer.from(ciphertextBase64, 'base64'),
  );
  return plaintext.toString('binary');
}

describe('encryptPasswordPkcs1v15 (browser entry, jsencrypt-backed)', () => {
  it('round-trips a plain ASCII password', () => {
    const password = 'correct horse battery staple';
    const ciphertextBase64 = encryptPasswordPkcs1v15(password, MODULUS_HEX, EXPONENT_HEX);
    expect(decryptWithFixture(ciphertextBase64)).toEqual(password);
  });

  it('encodes the password as binary (1 byte per char code), preserving high-bit bytes', () => {
    // Mirrors the node-entry contract: char codes are written as low-byte
    // bytes, NOT UTF-8 encoded. jsencrypt's default pkcs1pad2 would
    // UTF-8 expand 0xa9; our custom padding function in rsa.browser.ts
    // avoids that.
    const password = 'p©ssword'; // 0xa9 = copyright sign
    const ciphertextBase64 = encryptPasswordPkcs1v15(password, MODULUS_HEX, EXPONENT_HEX);
    expect(decryptWithFixture(ciphertextBase64)).toEqual(password);
  });

  it('returns valid base64 of full modulus byte length (256 for 2048-bit key)', () => {
    const ciphertextBase64 = encryptPasswordPkcs1v15('x', MODULUS_HEX, EXPONENT_HEX);
    expect(/^[A-Za-z0-9+/]+={0,2}$/.test(ciphertextBase64)).toEqual(true);
    expect(Buffer.from(ciphertextBase64, 'base64').length).toEqual(256);
  });

  it('pads odd-length exponent hex rather than silently truncating', () => {
    // Exasol's hex strings are typically even, but the helper is
    // defensive: pass an odd-length exponent and confirm the value
    // still parses to 65537 (the same key as EXPONENT_HEX = '010001').
    const oddExponentHex = '10001';
    expect(oddExponentHex.length % 2).toEqual(1);
    const password = 'odd-len';
    const ciphertextBase64 = encryptPasswordPkcs1v15(password, MODULUS_HEX, oddExponentHex);
    expect(decryptWithFixture(ciphertextBase64)).toEqual(password);
  });
});
