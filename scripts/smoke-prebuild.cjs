'use strict';

// Smoke test for the prebuilt binary.
//
// Confirms that the `prebuildify --napi` output in prebuilds/ is what actually
// loads (not a local dev build), that it is ABI-independent (no abi<N> tag, so
// one binary serves every Node version), and that its native functions work
// against a real SecureContext on the running Node. Run this across a matrix of
// Node versions in CI against the SAME prebuild to prove the single binary
// spans ABIs.
//
// PREBUILDS_ONLY makes node-gyp-build skip build/Release|Debug and resolve only
// from prebuilds/, so the check is meaningful even in a dev checkout that still
// has a build/ directory.

process.env.PREBUILDS_ONLY = '1';

const path = require('path');
const tls = require('tls');
const crypto = require('crypto');
const assert = require('assert');

const root = path.join(__dirname, '..');
const gypBuild = require('node-gyp-build/node-gyp-build.js');

function fail(message) {
  console.error('SMOKE FAIL: ' + message);
  process.exit(1);
}

function assertThrows(fn, what) {
  let threw = false;
  try { fn(); } catch { threw = true; }
  assert(threw, 'expected a throw: ' + what);
}

function main() {
  // 1. Resolve and prove we are loading a prebuild, not a dev build.
  let resolved;
  try {
    resolved = gypBuild.path(root);
  } catch (e) {
    fail('node-gyp-build found no prebuild: ' + e.message.split('\n')[0]);
  }
  const rel = path.relative(root, resolved);
  assert(rel.startsWith('prebuilds' + path.sep), 'expected a prebuild, resolved ' + rel);
  assert(!resolved.includes(path.sep + 'build' + path.sep), 'must not resolve to a dev build');

  // A --napi build carries no abi<N> tag, so it matches every Node ABI.
  assert(!/\babi\d+\b/.test(path.basename(resolved)),
    'prebuild ' + path.basename(resolved) + ' is ABI-locked; expected a --napi build');

  // 2. Load it and check the full export surface.
  const binding = gypBuild(root);
  for (const name of [
    'addCustomExtension', 'isPredefinedExtension', 'enableCompressCertificate',
    'enablePostHandshakeAuth', 'setOptions', 'clearOptions', 'constants',
  ]) {
    assert(name in binding, 'missing export: ' + name);
  }
  assert(typeof binding.constants.SSL_EXT_CLIENT_HELLO === 'number',
    'constants not populated');

  // 3. Exercise the native surface against a real SecureContext. This is the
  //    load-bearing check: it proves the napi_value->SSL_CTX bridge (GetSSLCtx)
  //    and the direct OpenSSL mutations work through the prebuilt binary on
  //    THIS Node ABI.
  const ctx = tls.createSecureContext({});
  binding.setOptions(ctx, crypto.constants.SSL_OP_NO_TICKET);
  binding.clearOptions(ctx, crypto.constants.SSL_OP_NO_TICKET);
  binding.enablePostHandshakeAuth(ctx);
  const customExt = 0xabcd; // private-use type, not internally handled by OpenSSL
  assert(!binding.isPredefinedExtension(customExt), 'test ext must be custom');
  binding.addCustomExtension(
    ctx, customExt, binding.constants.SSL_EXT_CLIENT_HELLO,
    Buffer.from([1, 2, 3]), null, null);

  // 4. Return values and validation behaviour.
  assert.strictEqual(typeof binding.isPredefinedExtension(13), 'boolean');
  assertThrows(() => binding.isPredefinedExtension(-1), 'strict integer validation');
  assertThrows(() => binding.setOptions({}, 0), 'rejects non-SecureContext');

  console.log(
    'OK  node ' + process.version + ' (abi ' + process.versions.modules + ') loaded ' +
    path.basename(resolved) + ' from prebuilds and exercised the native API');
}

try {
  main();
} catch (e) {
  fail(e.message);
}
