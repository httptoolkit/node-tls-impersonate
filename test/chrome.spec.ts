import { expect } from 'chai';
import { impersonate } from '../src/index.js';
import type { ClientHelloSpec } from '../src/index.js';
import { captureClientHello, expectedFailure } from './test-helpers.js';

// Chrome 133+ ClientHello spec
const chromeSpec: ClientHelloSpec = {
    cipherSuites: [
        0x3a3a, // GREASE cipher (skipped by impersonate, not in fingerprint)
        // TLS 1.3 (Chrome order: AES-128-GCM, AES-256-GCM, ChaCha20)
        0x1301, 0x1302, 0x1303,
        // TLS 1.2 (Chrome order)
        0xc02b, 0xc02f, 0xc02c, 0xc030,
        0xcca9, 0xcca8,
        0xc013, 0xc014,
        0x009c, 0x009d, 0x002f, 0x0035,
    ],
    extensions: [
        { type: 0x2a2a }, // GREASE extension 1
        { type: 0 },      // server_name
        { type: 23 },     // extended_master_secret
        { type: 65281 },  // renegotiation_info
        { type: 10 },     // supported_groups
        { type: 11 },     // ec_point_formats
        { type: 35 },     // session_ticket
        { type: 16 },     // ALPN
        { type: 5 },      // status_request (OCSP)
        { type: 18 },     // signed_certificate_timestamp (default: empty)
        { type: 27, data: Buffer.from([0x02, 0x00, 0x02]) }, // compress_certificate: brotli only
        { type: 13 },     // signature_algorithms
        { type: 43 },     // supported_versions
        { type: 45 },     // psk_key_exchange_modes
        { type: 51 },     // key_share
        { type: 17613 },  // application_settings (ALPS, default data: "h2")
        { type: 65037 },  // encrypted_client_hello (GREASE ECH, default data)
        { type: 0x4a4a }, // GREASE extension 2
    ],
    supportedGroups: [
        0x6a6a, // GREASE group (skipped)
        0x11ec, 0x001d, 0x0017, 0x0018,
    ],
    signatureAlgorithms: [
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ],
    alpnProtocols: ['h2', 'http/1.1'],
};

// Expected extension set (GREASE-filtered), in the order Chrome sends them
const CHROME_EXPECTED_EXTENSIONS = [0, 23, 65281, 10, 11, 35, 16, 5, 18, 27, 13, 43, 45, 51, 17613, 65037];

// Expected JA3 hash (assumes correct ec_point_formats: [0] uncompressed only)
const CHROME_EXPECTED_JA3 = 'f418dd9b4f923541607d5763fa771b1f';

// Expected full JA4 fingerprint
const CHROME_EXPECTED_JA4 = 't13d1516h2_8daaf6152771_d8a2da3f94cd';

describe('Chrome TLS fingerprint impersonation', () => {
    it('should match Chrome cipher suites exactly', async () => {
        const { secureContext, connectOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });
        const [, ciphers] = hello.fingerprintData;

        expect(ciphers).to.deep.equal([
            0x1301, 0x1302, 0x1303,
            0xc02b, 0xc02f, 0xc02c, 0xc030,
            0xcca9, 0xcca8,
            0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ]);
    });

    it('should match Chrome signature algorithms exactly', async () => {
        const { secureContext, connectOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });
        const [, , , , , sigAlgorithms] = hello.fingerprintData;

        expect(sigAlgorithms).to.deep.equal([
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ]);
    });

    it('should match Chrome supported groups exactly', async () => {
        const { secureContext, connectOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });
        const [, , , groups] = hello.fingerprintData;

        expect(groups).to.deep.equal([0x11ec, 0x001d, 0x0017, 0x0018]);
    });

    // Requires Node certificate compression support (pending Node PR 62217)
    it('should match Chrome extensions exactly', expectedFailure('*', async () => {
        const { secureContext, connectOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });
        const [, , extensions] = hello.fingerprintData;

        expect(new Set(extensions)).to.deep.equal(new Set(CHROME_EXPECTED_EXTENSIONS));
        expect(extensions).to.have.length(CHROME_EXPECTED_EXTENSIONS.length);
    }));

    // Requires OpenSSL EC point format fix (OpenSSL PR 26990)
    it('should send only uncompressed EC point format', expectedFailure('*', async () => {
        const { secureContext, connectOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });
        const [, , , , ecPointFormats] = hello.fingerprintData;

        expect(ecPointFormats).to.deep.equal([0]);
    }));

    // Depends on extensions and EC point formats being correct
    it('should match Chrome JA4 fingerprint', expectedFailure('*', async () => {
        const { secureContext, connectOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.ja4).to.equal(CHROME_EXPECTED_JA4);
    }));

    it('should match Chrome JA3 fingerprint', expectedFailure('*', async () => {
        const { secureContext, connectOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.ja3).to.equal(CHROME_EXPECTED_JA3);
    }));
});
