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
  // Crypto chunks are built FIRST so their .d.ts files exist on disk
  // by the time the main index bundle compiles sql-client.ts. The
  // package's `imports` map directs the TS plugin's `#crypto/rsa`
  // resolution to ./dist/crypto/rsa.node.d.ts via the `types` condition.
  //
  // Node crypto entry. Keeps node:crypto external. Emits a .d.ts so
  // consumers (and our own Rollup TS plugin compiling sql-client.ts)
  // can resolve types for `#crypto/rsa` via the `types` condition in
  // the package's imports map.
  {
    input: 'src/lib/crypto/rsa.node.ts',
    output: {
      file: 'dist/crypto/rsa.node.js',
      format: 'esm',
    },
    external: externalIds,
    plugins: [
      typescript({
        declaration: true,
        declarationDir: 'dist/crypto',
        rootDir: 'src/lib/crypto',
        exclude: ['**/*.spec.ts', '**/*.spec.dom.ts', '**/*.spec.node.ts'],
      }),
    ],
  },
  // Browser crypto entry. jsencrypt is left external so the consumer's
  // bundler can dedupe it. Declarations are emitted for symmetry.
  {
    input: 'src/lib/crypto/rsa.browser.ts',
    output: {
      file: 'dist/crypto/rsa.browser.js',
      format: 'esm',
    },
    external: externalIds,
    plugins: [
      typescript({
        declaration: true,
        declarationDir: 'dist/crypto',
        rootDir: 'src/lib/crypto',
        exclude: ['**/*.spec.ts', '**/*.spec.dom.ts', '**/*.spec.node.ts'],
      }),
    ],
  },
  // Main CJS + ESM bundle. Built after the crypto chunks so the
  // `#crypto/rsa` types resolve against the freshly emitted .d.ts.
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
];
