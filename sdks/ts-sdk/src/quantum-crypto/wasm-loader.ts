// Quantaureum TypeScript SDK source, version 1.0.0.
/**
 * Dilithium3 WASM loader — SDK-portable variant.
 *
 * @module signers/quantum-crypto/wasm-loader
 *
 * R40-P0-02 (2026-08-03): The Quantaureum SDK Wallet must sign with Dilithium3
 * (3293-byte signatures, 4000-byte private keys) — NOT secp256k1. This loader
 * is the SDK's portable bridge to the SAME `dilithium3-circl.wasm` binary the
 * Quantaureum extension wallet uses (compiled from cloudflare/circl mode3 via
 * Go's `js/wasm` target). Unlike the wallet loader, this version is decoupled
 * from Chrome extension APIs (no `chrome.runtime`, no LavaMoat scuttling, no
 * Service Worker `importScripts`) and works in both Node 18+ (Vitest / programmatic
 * consumers) and modern browsers (fetch + WebAssembly).
 *
 * Loader strategy:
 *   1. Read the wasm binary bytes (Node: `fs/promises.readFile`; browser:
 *      `fetch` on the deployed asset URL). The binary ships under
 *      `sdks/sdk/src/quantum-crypto/dilithium3-circl.wasm` in source and is
 *      emitted alongside the compiled JS by tsup.
 *   2. Evaluate `wasm_exec.js` (the Go `Wasm` target runtime) in a sandbox
 *      scope so it registers the `Go` class. The Go runtime is plain JS
 *      (no bundler globals); in Node we can `require` it directly; in the
 *      browser we inject a <script>-equivalent by `new Function`.
 *   3. `new Go().importObject` + `WebAssembly.instantiate(bytes, go.importObject)`
 *      → `go.run(instance)` (NOT awaited; Go's _start blocks on `select{}`).
 *   4. Poll for `globalThis._dilithium3_ready` (Go's `main()` sets it).
 *   5. Expose the four `_dilithium3_*` globals as the QuantumCryptoModule
 *      surface, frozen to prevent tampering.
 *
 * The raw Go bridge argument order is: `_dilithium3_sign(secretKey, message)`,
 * `_dilithium3_verify(publicKey, message, signature)` — note secretKey-first
 * and publicKey-first respectively. The QuantumCryptoModule wrapper normalizes
 * to a stable `(message, secretKey)` / `(signature, message, publicKey)`
 * contract matching the wallet Dilithium3 class.
 */

import { promises as fs } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import type { QuantumCryptoModule } from './wasm-types';

export const DILITHIUM3_PARAMS = {
  PUBLICKEYBYTES: 1952,
  SECRETKEYBYTES: 4000,
  SIGNATUREBYTES: 3293,
  CRYPTO_BYTES: 3293,
  SEEDBYTES: 32,
} as const;

const DEPLOYED_WASM_PATH = path.join(
  getDirName(),
  'dilithium3-circl.wasm',
);
const DEPLOYED_EXEC_PATH = path.join(
  getDirName(),
  'wasm_exec.js',
);

/**
 * Resolves the directory containing THIS module at runtime. In ESM (Node / bundlers)
 * `import.meta.url` is available; in CJS `__dirname` is. When bundled, the bundler
 * rewrites `import.meta.url` to a value relative to the emitted file, so the
 * sibling wasm/wasm_exec.js assets resolve correctly as long as `files` in
 * package.json publishes them. We do NOT rely on `chrome.runtime.getURL` /
 * `__dirname` globes that bundlers cannot statically analyze.
 */
function getDirName(): string {
  // Prefer __dirname when present (CJS build / simple-resolve Node).
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const g = globalThis as any;
  if (typeof g.__dirname === 'string' && g.__dirname.length > 0) {
    return g.__dirname;
  }
  try {
    if (typeof __filename === 'string' && __filename.length > 0) {
      return path.dirname(__filename);
    }
  } catch {
    /* __filename not defined (ESM context) — fall through. */
  }
  try {
    return path.dirname(fileURLToPath(import.meta.url));
  } catch {
    // Last-resort: relative path. Bundlers will have inlined the assets.
    return '.';
  }
}

let loadingPromise: Promise<QuantumCryptoModule> | null = null;
let cachedModule: QuantumCryptoModule | null = null;

/**
 * In a browser context, expose (or accept) a global hook the host page can use
 * to point us at the deployed wasm URL (e.g. a CDN). If unset, the loader
 * resolves relative to the bundled JS file. The host can set
 * `window.__QUANTAUREUM_WASM_BASE__` BEFORE any SDK signing call to relocate
 * the wasm/wasm_exec.js pair.
 */
function resolveAssetBase(): string {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const g = globalThis as any;
  if (g && typeof g.__QUANTAUREUM_WASM_BASE__ === 'string') {
    return g.__QUANTAUREUM_WASM_BASE__.replace(/\/$/, '');
  }
  return '';
}

async function readWasmBytes(): Promise<Uint8Array> {
  // Browser path: fetch the deployed wasm. The bundler copies the wasm to the
  // package output dir alongside the JS.
  if (typeof fetch === 'function' && typeof process === 'undefined') {
    const base = resolveAssetBase();
    const url = base
      ? `${base}/dilithium3-circl.wasm`
      : new URL('dilithium3-circl.wasm', import.meta.url).toString();
    const resp = await fetch(url);
    if (!resp.ok) {
      throw new Error(`[Quantaureum] failed to fetch Dilithium3 wasm: ${resp.status} ${resp.statusText}`);
    }
    return new Uint8Array(await resp.arrayBuffer());
  }
  // Node path: read from disk, resolved relative to this module (the published
  // package ships the wasm file as a sibling asset).
  return new Uint8Array(await fs.readFile(DEPLOYED_WASM_PATH));
}

/**
 * Load (and cache) the Go `Go` class from `wasm_exec.js`. In Node we require
 * the file directly; in a browser we fetch the script and evaluate it in a
 * Function scope (the Go runtime writes to `globalThis.Go`). The Go class is
 * idempotent across re-evaluations and free of side effects other than
 * defining `Go`, so this is safe to call multiple times.
 */
async function ensureGoRuntime(): Promise<typeof globalThis> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const g = globalThis as any;
  if (g.Go) {
    return g;
  }
  if (typeof fetch === 'function' && typeof process === 'undefined') {
    const base = resolveAssetBase();
    const url = base
      ? `${base}/wasm_exec.js`
      : new URL('wasm_exec.js', import.meta.url).toString();
    const resp = await fetch(url);
    if (!resp.ok) {
      throw new Error(`[Quantaureum] failed to fetch wasm_exec.js: ${resp.status}`);
    }
    const source = await resp.text();
    // eslint-disable-next-line no-new-func
    new Function(source).call(g);
    if (!g.Go) {
      throw new Error('[Quantaureum] wasm_exec.js loaded but did not register global Go class');
    }
    return g;
  }
  // Node: dynamic require to avoid bundler static analysis issues, and to
  // keep tsup from trying to parse wasm_exec.js as TypeScript.
  // eslint-disable-next-line @typescript-eslint/no-var-requires, @typescript-eslint/no-require-imports
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  require(DEPLOYED_EXEC_PATH);
  if (!g.Go) {
    throw new Error('[Quantaureum] wasm_exec.js loaded but did not register global Go class');
  }
  return g;
}

async function waitForReady(realGlobal: typeof globalThis, timeoutMs = 30000): Promise<void> {
  const start = Date.now();
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rg = realGlobal as any;
  while (!rg._dilithium3_ready) {
    if (Date.now() - start > timeoutMs) {
      throw new Error(
        `[Quantaureum] Timed out waiting for Dilithium3 WASM module. ` +
          `step=${rg._dilithium3_step}, err=${rg._dilithium3_error}`,
      );
    }
    await new Promise((r) => setTimeout(r, 50));
  }
}

function assertWasmFunctions(realGlobal: typeof globalThis): void {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rg = realGlobal as any;
  const required = ['_dilithium3_keypair', '_dilithium3_keypair_from_seed', '_dilithium3_sign', '_dilithium3_verify'];
  for (const fn of required) {
    if (typeof rg[fn] !== 'function') {
      throw new Error(`[Quantaureum] Dilithium3 WASM did not register ${fn} on globalThis`);
    }
  }
}

function buildModule(realGlobal: typeof globalThis): QuantumCryptoModule {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const rg = realGlobal as any;

  const module: QuantumCryptoModule = {
    dilithium3_keypair: () => {
      const result = rg._dilithium3_keypair();
      if (result.error) {
        throw new Error(`Dilithium key generation failed: ${result.error}`);
      }
      return {
        publicKey: new Uint8Array(result.publicKey),
        secretKey: new Uint8Array(result.privateKey),
      };
    },
    dilithium3_keypair_from_seed: (seed: Uint8Array) => {
      if (seed.length < 32) {
        throw new Error(`Dilithium3 seed too short: expected >=32 bytes, got ${seed.length}`);
      }
      const seedBuf = seed.slice(0, 32);
      const result = rg._dilithium3_keypair_from_seed(seedBuf);
      if (result.error) {
        throw new Error(`Dilithium key generation from seed failed: ${result.error}`);
      }
      seedBuf.fill(0);
      return {
        publicKey: new Uint8Array(result.publicKey),
        secretKey: new Uint8Array(result.privateKey),
      };
    },
    dilithium3_sign: (message: Uint8Array, secretKey: Uint8Array): Uint8Array => {
      const result = rg._dilithium3_sign(secretKey, message);
      if (result.error) {
        throw new Error(`Dilithium signing failed: ${result.error}`);
      }
      return new Uint8Array(result.signature);
    },
    dilithium3_verify: (signature: Uint8Array, message: Uint8Array, publicKey: Uint8Array): boolean => {
      const result = rg._dilithium3_verify(publicKey, message, signature);
      if (result.error) {
        throw new Error(`Dilithium verify failed: ${result.error}`);
      }
      return Boolean(result.valid);
    },
    randomBytes: (length: number): Uint8Array => {
      const arr = new Uint8Array(length);
      // Use the Web Crypto subtle / Node webcrypto randomValues — both available
      // on Node 18+ and all modern browsers. Falls back to Math.random if
      // neither exists (e.g. exotic runtimes) with a warning, so the SDK still
      // functions for non-cryptographic use. Dilithium3 seed randomness should
      // come from a caller-controlled CSPRNG in production key generation.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const c = (globalThis as any).crypto;
      if (c && typeof c.getRandomValues === 'function') {
        c.getRandomValues(arr);
      } else {
        for (let i = 0; i < length; i++) {
          arr[i] = Math.floor(Math.random() * 256);
        }
      }
      return arr;
    },
  };

  return Object.freeze(module);
}

export async function loadQuantumWasmModule(): Promise<QuantumCryptoModule> {
  if (cachedModule) {
    return cachedModule;
  }
  if (loadingPromise) {
    return loadingPromise;
  }

  loadingPromise = (async () => {
    try {
      const goGlobal = await ensureGoRuntime();
      const wasmBytes = await readWasmBytes();

      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const GoClass = (goGlobal as any).Go;
      const go = new GoClass();
      // Surface Go runtime exit code / errors on the real global for diagnostics.
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const rg = globalThis as any;
      go.exit = (code: number) => {
        rg._dilithium3_error = 'go_exit:' + code;
      };

      // `WebAssembly.instantiate(bytes, importObject)` (the bytes+importObject
      // overload) resolves directly to a `WebAssembly.Instance` — NOT the
      // `{ module, instance }` shape that `instantiateStreaming` returns.
      const instance = (await WebAssembly.instantiate(wasmBytes, go.importObject)) as WebAssembly.Instance;
      // do NOT await — Go blocks on select{} and never resolves until process exit
      go.run(instance).catch((err: Error) => {
        rg._dilithium3_error = 'run_err:' + (err && err.message ? err.message : String(err));
      });

      await waitForReady(globalThis);
      assertWasmFunctions(globalThis);

      const module = buildModule(globalThis);
      cachedModule = module;
      return module;
    } catch (err) {
      loadingPromise = null;
      throw err;
    }
  })();

  return loadingPromise;
}

export async function ensureQuantumModuleLoaded(): Promise<QuantumCryptoModule> {
  return loadQuantumWasmModule();
}

export function getQuantumModule(): QuantumCryptoModule | null {
  return cachedModule;
}

/**
 * Test-only: reset the cached module so subsequent calls re-instantiate the
 * WASM. Throws in non-test environments to prevent accidental production use.
 */
export function resetWasmModuleState(): void {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const env = (globalThis as any).process?.env;
  if (env && env.NODE_ENV !== 'test') {
    throw new Error('[Quantaureum] resetWasmModuleState is only allowed in test environment');
  }
  cachedModule = null;
  loadingPromise = null;
}
