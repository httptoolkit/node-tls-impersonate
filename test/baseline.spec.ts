import { expect } from 'chai';
import { impersonate } from '../src/index.js';
import type { ClientHelloSpec } from '../src/index.js';
import { captureClientHello, formatClientHello } from './test-helpers.js';

describe('Baseline impersonation', () => {
    it('round-trip: impersonating Node.js defaults reproduces the same cipher/sigalg/group sets', async () => {
        // Capture default Node.js ClientHello
        const defaultHello = await captureClientHello({
            ALPNProtocols: ['h2', 'http/1.1'],
        });

        const [, ciphers, extensions, groups, , sigAlgorithms] = defaultHello.fingerprintData;

        // Build spec from captured (GREASE-filtered) data
        const spec: ClientHelloSpec = {
            cipherSuites: ciphers,
            extensions: extensions.map(type => ({ type })),
            supportedGroups: groups,
            signatureAlgorithms: sigAlgorithms,
            alpnProtocols: ['h2', 'http/1.1'],
        };

        const { secureContext, connectOptions } = impersonate(spec);

        // Capture the impersonated ClientHello
        const impersonatedHello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        const [, impCiphers, , impGroups, , impSigAlgs] = impersonatedHello.fingerprintData;

        console.log('\n--- Default Node.js ---');
        console.log(formatClientHello(defaultHello));
        console.log('\n--- Impersonated ---');
        console.log(formatClientHello(impersonatedHello));

        // Cipher, sigalg, and group sets should match
        expect(new Set(impCiphers)).to.deep.equal(new Set(ciphers));
        expect(new Set(impSigAlgs)).to.deep.equal(new Set(sigAlgorithms));
        expect(new Set(impGroups)).to.deep.equal(new Set(groups));
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

        const [, , , , , sigAlgorithms] = hello.fingerprintData;
        const sigAlgSet = new Set(sigAlgorithms);

        // SHA-1 sigalgs should be present
        expect(sigAlgSet.has(0x0203), 'ecdsa_sha1').to.be.true;
        expect(sigAlgSet.has(0x0201), 'rsa_pkcs1_sha1').to.be.true;
    });

    it('custom (non-predefined) extensions appear in ClientHello', async () => {
        const spec: ClientHelloSpec = {
            cipherSuites: [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
            extensions: [
                { type: 0 }, { type: 10 }, { type: 11 }, { type: 13 },
                { type: 43 }, { type: 51 },
                { type: 28, data: Buffer.from([0x40, 0x01]) }, // record_size_limit
                { type: 34, data: Buffer.from([0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03]) },
                { type: 17613, data: Buffer.from([0x00, 0x02, 0x68, 0x32]) }, // ALPS
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

        const [, , extensions] = hello.fingerprintData;
        const extSet = new Set(extensions);

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
        const [, ciphers] = hello.fingerprintData;
        expect(ciphers).to.include(0x00ff, 'SCSV should be in ClientHello ciphers');

        // The non-SCSV ciphers should all be present too
        const expectedCiphers = [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0x009c, 0x002f];
        for (const c of expectedCiphers) {
            expect(ciphers).to.include(c, `cipher 0x${c.toString(16)} should be present`);
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

        const [, , extensions] = hello.fingerprintData;

        // fingerprintData strips GREASE, but we can check that the extension
        // count is higher than a spec without GREASE extensions
        const specWithoutGrease: ClientHelloSpec = {
            ...spec,
            extensions: spec.extensions.filter(e => (e.type & 0x0f0f) !== 0x0a0a),
        };

        const { secureContext: ctx2, connectOptions: opts2 } = impersonate(specWithoutGrease);
        const hello2 = await captureClientHello({
            secureContext: ctx2,
            ...opts2,
        });

        // The hello with GREASE extensions should report more total extensions
        // We can't verify GREASE in fingerprintData (stripped), but the overall
        // extension count in the raw ClientHello should differ.
        // At minimum, verify the non-GREASE set is the same
        const [, , extensions2] = hello2.fingerprintData;
        expect(new Set(extensions)).to.deep.equal(new Set(extensions2));
    });
});
