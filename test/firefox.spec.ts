import { expect } from 'chai';
import { impersonate } from '../src/index.js';
import type { ClientHelloSpec } from '../src/index.js';
import { captureClientHello, expectedFailure, runRealWorldTests } from './test-helpers.js';

// Firefox 133+ ClientHello spec
const firefoxSpec: ClientHelloSpec = {
    cipherSuites: [
        // TLS 1.3 (Firefox order: AES-128-GCM, ChaCha20, AES-256-GCM)
        0x1301, 0x1303, 0x1302,
        // TLS 1.2 ECDHE+ECDSA/RSA, then RSA-only
        0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
        0xc00a, 0xc009, 0xc013, 0xc014,
        0x009c, 0x009d, 0x002f, 0x0035,
    ],
    extensions: [
        { type: 0 },     // server_name
        { type: 23 },    // extended_master_secret
        { type: 65281 }, // renegotiation_info
        { type: 10 },    // supported_groups
        { type: 11 },    // ec_point_formats
        { type: 35 },    // session_ticket
        { type: 16 },    // ALPN
        { type: 5 },     // status_request (OCSP)
        { type: 34 },    // delegated_credentials (default data)
        { type: 28 },    // record_size_limit (default data: 16385)
        { type: 18 },    // signed_certificate_timestamp (default: empty)
        { type: 27, data: Buffer.from([0x06, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03]) },
        { type: 13 },    // signature_algorithms
        { type: 43 },    // supported_versions
        { type: 45 },    // psk_key_exchange_modes
        { type: 51 },    // key_share
        { type: 49 },    // post_handshake_auth
        { type: 65037 }, // encrypted_client_hello (GREASE ECH, default data)
    ],
    supportedGroups: [0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101],
    signatureAlgorithms: [
        0x0403, 0x0503, 0x0603,
        0x0804, 0x0805, 0x0806,
        0x0401, 0x0501, 0x0601,
        0x0203, 0x0201, // SHA-1 variants
    ],
    alpnProtocols: ['h2', 'http/1.1'],
};

// Expected extension set (no GREASE in Firefox spec)
const FIREFOX_EXPECTED_EXTENSIONS = [0, 23, 65281, 10, 11, 35, 16, 5, 34, 28, 18, 27, 13, 43, 45, 51, 49, 65037];

// Expected JA3 hash (assumes correct ec_point_formats: [0] uncompressed only)
const FIREFOX_EXPECTED_JA3 = 'f656f04be2b252871dab2584ff3392a5';

// Expected full JA4 fingerprint
const FIREFOX_EXPECTED_JA4 = 't13d1718h2_5b57614c22b0_1ae7ba31360c';

describe('Firefox TLS fingerprint impersonation', () => {
    it('should match Firefox cipher suites exactly', async () => {
        const { secureContext, connectOptions } = impersonate(firefoxSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.ciphers).to.deep.equal([
            0x1301, 0x1303, 0x1302,
            0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
            0xc00a, 0xc009, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ]);
    });

    it('should match Firefox signature algorithms exactly', async () => {
        const { secureContext, connectOptions } = impersonate(firefoxSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.signatureAlgorithms).to.deep.equal([
            0x0403, 0x0503, 0x0603,
            0x0804, 0x0805, 0x0806,
            0x0401, 0x0501, 0x0601,
            0x0203, 0x0201,
        ]);
    });

    it('should match Firefox supported groups exactly', async () => {
        const { secureContext, connectOptions } = impersonate(firefoxSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.groups).to.deep.equal([0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101]);
    });

    // Requires Node's bundled OpenSSL to be built with certificate compression
    // enabled (ext 27). First available in Node 26.4.0; earlier builds omit it.
    it('should match Firefox extensions exactly', expectedFailure('<26.4.0', async () => {
        const { secureContext, connectOptions } = impersonate(firefoxSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(new Set(hello.extensions)).to.deep.equal(new Set(FIREFOX_EXPECTED_EXTENSIONS));
        expect(hello.extensions).to.have.length(FIREFOX_EXPECTED_EXTENSIONS.length);
    }));

    // Requires OpenSSL EC point format fix (OpenSSL PR 26990)
    it('should send only uncompressed EC point format', expectedFailure('*', async () => {
        const { secureContext, connectOptions } = impersonate(firefoxSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.ecPointFormats).to.deep.equal([0]);
    }));

    // Depends on the correct extension set (certificate compression, Node 26.4.0+).
    // Unlike JA3, JA4 does not hash EC point formats, so it passes without OpenSSL PR 26990.
    it('should match Firefox JA4 fingerprint', expectedFailure('<26.4.0', async () => {
        const { secureContext, connectOptions } = impersonate(firefoxSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.ja4).to.equal(FIREFOX_EXPECTED_JA4);
    }));

    it('should match Firefox JA3 fingerprint', expectedFailure('*', async () => {
        const { secureContext, connectOptions } = impersonate(firefoxSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.ja3).to.equal(FIREFOX_EXPECTED_JA3);
    }));

    runRealWorldTests('Firefox', firefoxSpec);
});
