# TLS Impersonate [![Build Status](https://github.com/httptoolkit/node-tls-impersonate/workflows/CI/badge.svg)](https://github.com/httptoolkit/node-tls-impersonate/actions) [![Available on NPM](https://img.shields.io/npm/v/tls-impersonate.svg)](https://npmjs.com/package/tls-impersonate)

> _Part of [HTTP Toolkit](https://httptoolkit.com): powerful tools for building, testing & debugging HTTP(S)_

Reproduce arbitrary TLS ClientHello fingerprints (JA3/JA4) while using Node.js's normal networking APIs.

Servers and anti-bot systems increasingly fingerprint the exact shape of a TLS ClientHello - its cipher suites, extensions, supported groups and their ordering - to tell real browsers apart from other clients. Node.js sends its own recognisable fingerprint, and limited options to change it.

This library takes a target ClientHello specification and builds a standard [`tls.SecureContext`](https://nodejs.org/api/tls.html#tlscreatesecurecontextoptions) which reproduces that fingerprint as closely as possible. The result plugs straight into `tls.connect`, `https`, or any Node API that accepts a secure context, and can perfectly match Chrome, Firefox, Safari, curl, and others on modern Node releases.

## Installation

This requires Node >= 24.15.0, and >= 26.4.0 is strongly recommended as it's required to fully match browser fingerprints.

```bash
npm install tls-impersonate
```

This is a native module, but prebuilds are included for most platforms.

## Usage

Pass a full ClientHello specification to `impersonate()`, then spread `...tlsOptions` into your connection options:

```typescript
import * as tls from 'node:tls';
import { impersonate } from 'tls-impersonate';

const { tlsOptions, unsupported } = impersonate({
    cipherSuites: [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, /* ... */],
    extensions: [
        { type: 0x0000 }, // server_name
        { type: 0x0017 }, // extended_master_secret
        { type: 0x0010 }, // ALPN
        // ...in wire order, including GREASE
    ],
    supportedGroups: [0x001d, 0x0017, 0x0018],
    signatureAlgorithms: [0x0403, 0x0804, 0x0401],
    alpnProtocols: ['h2', 'http/1.1']
});

const socket = tls.connect({
    host: 'testserver.host',
    port: 443,
    servername: 'testserver.host',
    ...tlsOptions
});
```

The options configured in TLS options are those supported by Node's built-in [`tls` module](https://nodejs.org/api/tls.html) and can be passed to any function which accepts these - this includes the built-in `https` module and anything else which passes options through to it.

`impersonate()` never throws for parts of the fingerprint it can't reproduce - it always produces the closest achievable ClientHello and reports any gaps in the `unsupported` array, so you can log or monitor them:

```typescript
for (const gap of unsupported) {
    console.warn(`Could not reproduce ${gap.kind} ${gap.id}: ${gap.reason}`);
}
```

### Impersonating a captured ClientHello

If you have a real ClientHello parsed with [read-tls-client-hello](https://github.com/httptoolkit/read-tls-client-hello), you can pass it straight in - no need to build a spec by hand:

```typescript
import { impersonateFromClientHello } from 'tls-impersonate';
import { readTlsClientHello } from 'read-tls-client-hello';

const hello = await readTlsClientHello(capturedStream);
const { tlsOptions } = impersonateFromClientHello(hello);

const socket = tls.connect({
    host: 'testserver.host',
    port: 443,
    servername: 'testserver.host',
    ...tlsOptions
});
```

### Security

By default, tls-impersonate will never reduce the security of TLS connections. It will not change the OpenSSL security level, and although it advertises some legacy features it will reject any connections that attempt to use them.

This works for almost all fingerprints, but not 100% of cases. If this is not sufficient (as reported by the `unsupported` result) you can pass `securiry: 'insecure'` to allow tls-impersonate to enable known-insecure configurations. This should be avoided unless absolutely necessary, and this isn't required to match the fingerprints of most clients (browsers, Android HTTP libraries, etc).

### Feature detection

Impersonation depends on internals that are only present on supported modern Node runtimes. Check availability once at startup and fall back to Node's default TLS if it's missing:

```typescript
import { isSupported } from 'tls-impersonate';

if (!isSupported()) {
    // Wrong Node version, unsupported platform, or the native addon failed to load.
}
```