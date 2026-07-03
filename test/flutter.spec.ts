import { expect } from 'chai';
import { impersonate } from '../src/index.js';
import type { ClientHelloSpec } from '../src/index.js';
import { captureClientHello, expectedFailure, runRealWorldTests } from './test-helpers.js';

// Flutter / Dart 3.11 HTTP client ClientHello, captured from an Android 16 device.
const dartSpec: ClientHelloSpec = {
    cipherSuites: [
        // TLS 1.3 (Flutter/BoringSSL order: ChaCha20, AES-128, AES-256)
        0x1303, 0x1301, 0x1302,
        // TLS 1.2 ECDHE (ChaCha20 first, then GCM, then CBC)
        0xcca9, 0xcca8,
        0xc02b, 0xc02f, 0xc02c, 0xc030,
        0xc009, 0xc013, 0xc00a, 0xc014,
        // TLS 1.2 RSA
        0x009c, 0x009d, 0x002f, 0x0035,
    ],
    extensions: [
        { type: 0 },     // server_name
        { type: 23 },    // extended_master_secret
        { type: 65281 }, // renegotiation_info
        { type: 10 },    // supported_groups
        { type: 11 },    // ec_point_formats
        { type: 35 },    // session_ticket
        { type: 13 },    // signature_algorithms
        { type: 51 },    // key_share
        { type: 45 },    // psk_key_exchange_modes
        { type: 43 },    // supported_versions
    ],
    supportedGroups: [0x001d, 0x0017, 0x0018],
    signatureAlgorithms: [
        0x0403, 0x0804, 0x0401,
        0x0503, 0x0805, 0x0501,
        0x0806, 0x0601,
        0x0201,
    ],
    // Flutter doesn't set ALPN by default
};

const DART_EXPECTED_JA3 = '9225d95490794840d9d5f1f94d339285';
const DART_EXPECTED_JA4 = 't13d171000_5b57614c22b0_78e6aca7449b';

describe('Flutter TLS fingerprint impersonation', () => {
    it('should match Flutter cipher suites exactly', async () => {
        const { secureContext, connectOptions } = impersonate(dartSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.ciphers).to.deep.equal([
            0x1303, 0x1301, 0x1302,
            0xcca9, 0xcca8,
            0xc02b, 0xc02f, 0xc02c, 0xc030,
            0xc009, 0xc013, 0xc00a, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ]);
    });

    it('should match Flutter signature algorithms exactly', async () => {
        const { secureContext, connectOptions } = impersonate(dartSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.signatureAlgorithms).to.deep.equal([
            0x0403, 0x0804, 0x0401,
            0x0503, 0x0805, 0x0501,
            0x0806, 0x0601,
            0x0201,
        ]);
    });

    it('should match Flutter supported groups exactly', async () => {
        const { secureContext, connectOptions } = impersonate(dartSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.groups).to.deep.equal([0x001d, 0x0017, 0x0018]);
    });

    it('should match Flutter extensions exactly', async () => {
        const { secureContext, connectOptions } = impersonate(dartSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(new Set(hello.extensions)).to.deep.equal(new Set(
            [0, 23, 65281, 10, 11, 35, 13, 51, 45, 43]
        ));
        expect(hello.extensions).to.have.length(10);
    });

    // Requires OpenSSL EC point format fix (OpenSSL PR 26990)
    it('should send only uncompressed EC point format', expectedFailure('*', async () => {
        const { secureContext, connectOptions } = impersonate(dartSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.ecPointFormats).to.deep.equal([0]);
    }, () => {
        const { unsupported } = impersonate(dartSpec);
        expect(unsupported.some(u => u.kind === 'extension' && u.id === 11)).to.be.true;
    }));

    it('should match Flutter JA4 fingerprint', async () => {
        const { secureContext, connectOptions } = impersonate(dartSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.ja4).to.equal(DART_EXPECTED_JA4);
    });

    // JA3 includes EC point formats, so depends on OpenSSL PR 26990
    it('should match Flutter JA3 fingerprint', expectedFailure('*', async () => {
        const { secureContext, connectOptions } = impersonate(dartSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.ja3).to.equal(DART_EXPECTED_JA3);
    }, () => {
        const { unsupported } = impersonate(dartSpec);
        expect(unsupported.some(u => u.kind === 'extension' && u.id === 11)).to.be.true;
    }));

    runRealWorldTests('Flutter', dartSpec);
});
