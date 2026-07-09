import { expect } from 'chai';
import {
    impersonate,
    impersonateFromClientHello,
    isSupported,
} from '../src/index.js';
import type { ClientHelloSpec } from '../src/index.js';
import { captureClientHello } from './test-helpers.js';

// A GREASE-free spec, so the round-trip is deterministic (no randomised GREASE).
const spec: ClientHelloSpec = {
    cipherSuites: [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0x009c, 0x002f],
    extensions: [
        { type: 0 }, { type: 10 }, { type: 11 }, { type: 13 },
        { type: 16 }, { type: 43 }, { type: 45 }, { type: 51 },
    ],
    supportedGroups: [0x001d, 0x0017, 0x0018],
    signatureAlgorithms: [0x0403, 0x0804, 0x0401],
    alpnProtocols: ['h2', 'http/1.1'],
};

describe('isSupported()', () => {
    it('is true on this runtime (Node >= 24.15 exports GetSSLCtx)', () => {
        expect(isSupported()).to.equal(true);
    });

    it('agrees with impersonate() actually working', async () => {
        // If supported, impersonate() must not throw the runtime error.
        expect(isSupported()).to.equal(true);
        const { tlsOptions } = impersonate(spec);
        const hello = await captureClientHello(tlsOptions);
        expect(hello.ciphers).to.include(0x1301);
    });
});

describe('impersonateFromClientHello()', () => {
    it('reproduces a captured hello fed straight back in (round-trip)', async () => {
        const first = impersonate(spec);
        const hello1 = await captureClientHello({
            ...first.tlsOptions,
        });

        // Feed read-tls-client-hello's parsed message directly - no manual spec.
        const second = impersonateFromClientHello(hello1.raw);
        const hello2 = await captureClientHello({
            ...second.tlsOptions,
        });

        expect(hello2.ciphers).to.deep.equal(hello1.ciphers);
        expect(hello2.groups).to.deep.equal(hello1.groups);
        expect(hello2.signatureAlgorithms).to.deep.equal(hello1.signatureAlgorithms);
        expect(new Set(hello2.extensions)).to.deep.equal(new Set(hello1.extensions));
        // JA4 sorts extensions, so it is order-independent and must round-trip exactly.
        expect(hello2.ja4).to.equal(hello1.ja4);
    });
});
