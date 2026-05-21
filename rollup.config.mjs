import typescript from '@rollup/plugin-typescript';

import { readFileSync } from 'fs';
const pkg = JSON.parse(readFileSync('package.json', { encoding: 'utf8' }));

// Treat the imports-map specifier as external so the main bundle does
// not try to inline either crypto backend. Node resolves it via the
// package's `imports` field at runtime; bundlers (esbuild, webpack 5,
// vite, rollup) honor the same map.
const externalIds = [
  ...Object.keys(pkg.dependencies || {}),
  ...Object.keys(pkg.peerDependencies || {}),
  'node:crypto',
  '#crypto/rsa',
];

export default [
  // Main CJS + ESM bundle.
  {
    input: 'src/index.ts',
    output: [
      {
        file: pkg.main,
        format: 'cjs',
      },
      {
        file: pkg.module,
        format: 'esm',
      },
    ],
    external: externalIds,
    plugins: [typescript()],
  },
  // Node crypto entry. Keeps node:crypto external. Declarations are
  // disabled here; the package's `imports` map points TypeScript
  // consumers at the source .ts via the `types` condition.
  {
    input: 'src/lib/crypto/rsa.node.ts',
    output: {
      file: 'dist/crypto/rsa.node.js',
      format: 'esm',
    },
    external: externalIds,
    plugins: [typescript({ declaration: false, rootDir: 'src' })],
  },
  // Browser crypto entry. jsencrypt is left external so the consumer's
  // bundler can dedupe it.
  {
    input: 'src/lib/crypto/rsa.browser.ts',
    output: {
      file: 'dist/crypto/rsa.browser.js',
      format: 'esm',
    },
    external: externalIds,
    plugins: [typescript({ declaration: false, rootDir: 'src' })],
  },
];
