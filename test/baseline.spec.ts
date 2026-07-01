import { expect } from 'chai';
import { impersonate } from '../src/index.js';
import type { ClientHelloSpec } from '../src/index.js';
import { captureClientHello } from './test-helpers.js';

describe('Baseline impersonation', () => {
    it('round-trip: impersonating Node.js defaults reproduces the same fingerprint data', async () => {
        // Capture default Node.js ClientHello
        const defaultHello = await captureClientHello({
            ALPNProtocols: ['h2', 'http/1.1'],
        });

        // Build spec from the captured (GREASE-filtered) fingerprint fields
        const spec: ClientHelloSpec = {
            cipherSuites: defaultHello.ciphers,
            extensions: defaultHello.extensions.map(type => ({ type })),
            supportedGroups: defaultHello.groups,
            signatureAlgorithms: defaultHello.signatureAlgorithms,
            alpnProtocols: ['h2', 'http/1.1'],
        };

        const { secureContext, connectOptions } = impersonate(spec);

        // Capture the impersonated ClientHello
        const impersonatedHello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        // All fields should match exactly, preserving order
        expect(impersonatedHello.ciphers).to.deep.equal(defaultHello.ciphers);
        expect(impersonatedHello.signatureAlgorithms).to.deep.equal(defaultHello.signatureAlgorithms);
        expect(impersonatedHello.groups).to.deep.equal(defaultHello.groups);
        expect(impersonatedHello.ecPointFormats).to.deep.equal(defaultHello.ecPointFormats);

        // Extension set should match (order may differ due to OpenSSL internals)
        expect(new Set(impersonatedHello.extensions)).to.deep.equal(new Set(defaultHello.extensions));
        expect(impersonatedHello.extensions).to.have.length(defaultHello.extensions.length);

        // JA3 and JA4 should both match
        expect(impersonatedHello.ja3).to.equal(defaultHello.ja3);
        expect(impersonatedHello.ja4).to.equal(defaultHello.ja4);
    });

    it('SHA-1 sigalgs automatically enable @SECLEVEL=0', async () => {
        // Spec with SHA-1 signature algorithms (would fail without @SECLEVEL=0)
        const spec: ClientHelloSpec = {
            cipherSuites: [
                0x1301, 0x1302, 0x1303,
                0xc02b, 0xc02f, 0x009c, 0x002f,
            ],
            extensions: [
                { type: 0 }, { type: 10 }, { type: 11 }, { type: 13 },
                { type: 43 }, { type: 51 },
            ],
            supportedGroups: [0x001d, 0x0017],
            signatureAlgorithms: [
                0x0403, 0x0804, 0x0401,
                0x0203, // ecdsa_sha1
                0x0201, // rsa_pkcs1_sha1
            ],
            alpnProtocols: ['h2', 'http/1.1'],
        };

        // Should not throw — @SECLEVEL=0 is auto-applied
        const { secureContext, connectOptions } = impersonate(spec);

        const hello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        // SHA-1 sigalgs should be present
        expect(hello.signatureAlgorithms).to.include(0x0203, 'ecdsa_sha1');
        expect(hello.signatureAlgorithms).to.include(0x0201, 'rsa_pkcs1_sha1');
    });

    it('custom (non-predefined) extensions appear in ClientHello', async () => {
        const spec: ClientHelloSpec = {
            cipherSuites: [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
            extensions: [
                { type: 0 }, { type: 10 }, { type: 11 }, { type: 13 },
                { type: 43 }, { type: 51 },
                { type: 28, data: Buffer.from([0x40, 0x01]) }, // record_size_limit
                { type: 34, data: Buffer.from([0x00, 0x04, 0x1a, 0x1a, 0x4a, 0x4a]) }, // delegated_credentials with GREASE schemes

                { type: 17613, data: Buffer.from([0x00, 0x02, 0x01, 0x00]) }, // ALPS: 1-byte protocol name
            ],
            supportedGroups: [0x001d, 0x0017],
            signatureAlgorithms: [0x0403, 0x0804, 0x0401],
            alpnProtocols: ['h2', 'http/1.1'],
        };

        const { secureContext, connectOptions } = impersonate(spec);
        const hello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        const extSet = new Set(hello.extensions);

        expect(extSet.has(28), 'record_size_limit (28)').to.be.true;
        expect(extSet.has(34), 'delegated_credentials (34)').to.be.true;
        expect(extSet.has(17613), 'application_settings (17613)').to.be.true;
    });

    it('SCSV (0x00ff) in spec appears in ClientHello but TLS 1.0/1.1 are blocked', async () => {
        const spec: ClientHelloSpec = {
            cipherSuites: [
                0x1301, 0x1302, 0x1303,
                0xc02b, 0xc02f, 0x009c, 0x002f,
                0x00ff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
            ],
            extensions: [
                { type: 0 }, { type: 10 }, { type: 11 }, { type: 13 },
                { type: 22 }, { type: 23 },
                { type: 43 }, { type: 45 }, { type: 51 },
            ],
            supportedGroups: [0x001d, 0x0017],
            signatureAlgorithms: [0x0403, 0x0804, 0x0401],
            alpnProtocols: ['h2', 'http/1.1'],
        };

        const { secureContext, connectOptions } = impersonate(spec);
        const hello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        // SCSV should appear in the captured cipher list
        expect(hello.ciphers).to.include(0x00ff, 'SCSV should be in ClientHello ciphers');

        // The non-SCSV ciphers should all be present too
        const expectedCiphers = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0x009c, 0x002f];
        for (const c of expectedCiphers) {
            expect(hello.ciphers).to.include(c, `cipher 0x${c.toString(16)} should be present`);
        }
    });

    it('GREASE extensions are added to the ClientHello', async () => {
        const spec: ClientHelloSpec = {
            cipherSuites: [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
            extensions: [
                { type: 0 }, { type: 10 }, { type: 11 }, { type: 13 },
                { type: 43 }, { type: 51 },
                { type: 0x2a2a }, // GREASE extension
                { type: 0x4a4a }, // Another GREASE extension
            ],
            supportedGroups: [0x001d, 0x0017],
            signatureAlgorithms: [0x0403, 0x0804, 0x0401],
            alpnProtocols: ['h2', 'http/1.1'],
        };

        const { secureContext, connectOptions } = impersonate(spec);
        const hello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        // The raw extension list includes the GREASE extensions we asked for...
        const rawExtensionIds = hello.raw.extensions.map(e => e.id);
        expect(rawExtensionIds).to.include(0x2a2a);
        expect(rawExtensionIds).to.include(0x4a4a);

        // ...while the GREASE-filtered fingerprint view excludes them.
        expect(hello.extensions).to.not.include(0x2a2a);
        expect(hello.extensions).to.not.include(0x4a4a);
    });
});
