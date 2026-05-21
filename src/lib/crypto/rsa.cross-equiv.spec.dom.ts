/**
 * @jest-environment jsdom
 */
import { constants as cryptoConstants, createPrivateKey, privateDecrypt } from 'node:crypto';
import { encryptPasswordPkcs1v15 as encryptNode } from './rsa.node';
import { encryptPasswordPkcs1v15 as encryptBrowser } from './rsa.browser';

// Cross-implementation equivalence between the node and browser RSA
// backends. Both encrypt the same plaintext under the same public key,
// then we decrypt both ciphertexts with node:crypto.privateDecrypt and
// assert the plaintexts match the original input.
//
// Why this test exists: the browser backend reaches reflectively through
// jsencrypt's internals (`RSAKey.n.constructor` to grab the BigInteger
// constructor). A future jsencrypt minor bump could rename or hide that
// shape and the browser path would silently regress. This test fails
// loudly the first time the two backends diverge.
//
// Throwaway test-only RSA-2048 keypair. Generated once via Node so the
// same fixture decrypts whatever either backend emits. Keys are inline
// to keep keygen out of the test path (jsdom keygen would be slow and
// adds no signal).

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

describe('RSA PKCS1-v1.5 cross-implementation equivalence', () => {
  // 5 cases: ASCII, single high-bit char, all high-bit, empty, large payload.
  // For each, encrypt with both backends, decrypt both ciphertexts with
  // the same private key, assert both plaintexts equal the original.
  const cases: Array<{ name: string; password: string }> = [
    { name: 'plain ASCII', password: 'password123' },
    { name: 'high-bit char (0xa9)', password: 'p©ssword' },
    { name: 'all high-bit chars (0xff..0xfc)', password: 'ÿþýü' },
    { name: 'empty string', password: '' },
    {
      name: '~200-byte payload (under RSA-2048 PKCS1 max of 245)',
      password: 'A'.repeat(200),
    },
  ];

  for (const { name, password } of cases) {
    it(`node and browser backends agree on ${name}`, () => {
      const ciphertextNode = encryptNode(password, MODULUS_HEX, EXPONENT_HEX);
      const ciphertextBrowser = encryptBrowser(password, MODULUS_HEX, EXPONENT_HEX);

      const plaintextFromNode = decryptWithFixture(ciphertextNode);
      const plaintextFromBrowser = decryptWithFixture(ciphertextBrowser);

      // Both backends decrypt to the same plaintext (binary-equal).
      expect(plaintextFromBrowser).toEqual(plaintextFromNode);
      // And that plaintext is the original input under binary encoding.
      expect(plaintextFromNode).toEqual(password);
      expect(plaintextFromBrowser).toEqual(password);
    });
  }
});
