import * as tls from 'node:tls';
import { expect } from 'chai';
import { impersonate, impersonateFromClientHello } from '../src/index.js';
import type { ClientHelloSpec } from '../src/index.js';
import { bundlesOpenSsl4, captureClientHello } from './test-helpers.js';

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

        const { tlsOptions } = impersonate(spec);

        // Capture the impersonated ClientHello
        const impersonatedHello = await captureClientHello({
            ...tlsOptions,
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
        const { tlsOptions } = impersonate(spec);

        const hello = await captureClientHello({
            ...tlsOptions,
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

        const { tlsOptions } = impersonate(spec);
        const hello = await captureClientHello({
            ...tlsOptions,
        });

        const extSet = new Set(hello.extensions);

        expect(extSet.has(28), 'record_size_limit (28)').to.be.true;
        expect(extSet.has(34), 'delegated_credentials (34)').to.be.true;
        expect(extSet.has(17613), 'application_settings (17613)').to.be.true;
    });

    // SCSV is only emitted at OpenSSL security level 0, i.e. in 'insecure' mode.
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

        const { tlsOptions } = impersonate(spec, { security: 'insecure' });
        const hello = await captureClientHello({
            ...tlsOptions,
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

        const { tlsOptions } = impersonate(spec);
        const hello = await captureClientHello({
            ...tlsOptions,
        });

        // The raw extension list includes the GREASE extensions we asked for...
        const rawExtensionIds = hello.raw.extensions.map(e => e.id);
        expect(rawExtensionIds).to.include(0x2a2a);
        expect(rawExtensionIds).to.include(0x4a4a);

        // ...while the GREASE-filtered fingerprint view excludes them.
        expect(hello.extensions).to.not.include(0x2a2a);
        expect(hello.extensions).to.not.include(0x4a4a);
    });

    it('only advertises certificate compression algorithms this build supports', async () => {
        const spec: ClientHelloSpec = {
            cipherSuites: [0x1301, 0xc02b],
            extensions: [
                { type: 0 }, { type: 10 }, { type: 13 }, { type: 43 }, { type: 51 },
                { type: 27, data: Buffer.from([0x04, 0x00, 0x07 /* unknown */, 0x00, 0x02]) },
            ],
            supportedGroups: [0x001d, 0x0017],
            signatureAlgorithms: [0x0403],
        };

        const { tlsOptions, unsupported } = impersonate(spec);
        const hello = await captureClientHello(tlsOptions);
        const report = unsupported.find(u => u.kind === 'extension' && u.id === 27);

        if (tls.getCertificateCompressionAlgorithms === undefined) {
            expect(report?.reason).to.equal('certificate compression not available in this OpenSSL build');
            expect(hello.certCompressionAlgorithms).to.equal(undefined);
        } else {
            expect(report?.reason).to.equal(
                'some requested certificate compression algorithms are not available in this OpenSSL build');
            expect(hello.certCompressionAlgorithms).to.deep.equal([2]);
        }
    });

    it('degrades gracefully for unreproducible codepoints and reports them', async () => {
        const spec: ClientHelloSpec = {
            cipherSuites: [0x1301, 0xdead /* unknown */, 0xc02b],
            extensions: [
                { type: 0 }, { type: 10 }, { type: 11 }, { type: 13 },
                { type: 43 }, { type: 51 },
            ],
            supportedGroups: [0x001d, 0xbeef /* unknown */],
            signatureAlgorithms: [0x0403, 0x0555 /* unknown */],
            alpnProtocols: ['h2', 'http/1.1'],
        };

        // Does not throw; reports each unreproducible codepoint.
        const { tlsOptions, unsupported } = impersonate(spec);
        expect(unsupported.find(u => u.id === 0xdead)).to.deep.equal(
            { kind: 'cipherSuite', id: 0xdead, reason: 'not a known cipher suite' });
        expect(unsupported.find(u => u.id === 0xbeef)).to.deep.equal(
            { kind: 'supportedGroup', id: 0xbeef, reason: 'not a known supported group' });
        expect(unsupported.find(u => u.id === 0x0555)).to.deep.equal(
            { kind: 'signatureAlgorithm', id: 0x0555, reason: 'not a known signature algorithm' });

        // Still produces the closest fingerprint: known codepoints emitted,
        // unreproducible ones simply absent.
        const hello = await captureClientHello(tlsOptions);
        expect(hello.ciphers).to.include(0x1301).and.to.include(0xc02b);
        expect(hello.ciphers).to.not.include(0xdead);
        expect(hello.groups).to.include(0x001d).and.to.not.include(0xbeef);
    });

    it('falls back to default groups when no requested group is reproducible', async () => {
        const spec: ClientHelloSpec = {
            cipherSuites: [0x1301, 0xc02b],
            extensions: [{ type: 0 }, { type: 10 }, { type: 13 }, { type: 43 }, { type: 51 }],
            supportedGroups: [0xbeef /* unknown */],
            signatureAlgorithms: [0x0403],
        };

        const { tlsOptions, unsupported } = impersonate(spec);
        expect(unsupported.some(u => u.kind === 'extension' && u.id === 10)).to.be.true;

        // With no groups at all, OpenSSL can't build a TLS 1.3 ClientHello
        const hello = await captureClientHello(tlsOptions);
        expect(hello.groups).to.not.be.empty;
    });

    it('drops and reports groups and sigalgs this OpenSSL lacks', async () => {
        const spec: ClientHelloSpec = {
            cipherSuites: [0x1301, 0xc02b],
            extensions: [{ type: 0 }, { type: 10 }, { type: 13 }, { type: 43 }, { type: 51 }],
            supportedGroups: [0x001d, 0x0029 /* curveSM2, OpenSSL 4.0+ */, 0x0017],
            signatureAlgorithms: [0x0403, 0x0911 /* slhdsa_sha2_128s, OpenSSL 4.0+ */, 0x0804],
        };

        // The second call covers names already known to be unavailable
        for (let i = 0; i < 2; i++) {
            const { tlsOptions, unsupported } = impersonate(spec);
            const hello = await captureClientHello(tlsOptions);

            if (bundlesOpenSsl4) {
                expect(unsupported).to.deep.equal([]);
                expect(hello.groups).to.deep.equal([0x001d, 0x0029, 0x0017]);
                expect(hello.signatureAlgorithms).to.deep.equal([0x0403, 0x0911, 0x0804]);
            } else {
                expect(unsupported).to.have.deep.members([
                    { kind: 'supportedGroup', id: 0x0029, reason: 'not available in this OpenSSL build' },
                    { kind: 'signatureAlgorithm', id: 0x0911, reason: 'not available in this OpenSSL build' },
                ]);
                expect(hello.groups).to.deep.equal([0x001d, 0x0017]);
                expect(hello.signatureAlgorithms).to.deep.equal([0x0403, 0x0804]);
            }
        }
    });
});
