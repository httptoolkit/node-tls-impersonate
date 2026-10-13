import { expect } from 'chai';
import { impersonate } from '../src/index.js';
import type { ClientHelloSpec } from '../src/index.js';
import { captureClientHello, expectedFailure, runRealWorldTests } from './test-helpers.js';

// Chrome 155 ClientHello spec
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
        { type: 4832 },   // server_padding
        { type: 51764 },  // trust_anchors
        { type: 17613 },  // application_settings (ALPS, default data: "h2")
        { type: 65037 },  // encrypted_client_hello (GREASE ECH, default data)
        { type: 0x4a4a }, // GREASE extension 2
    ],
    supportedGroups: [
        0x6a6a, // GREASE group (skipped)
        0x11ec, 0x001d, 0x0017, 0x0018,
    ],
    signatureAlgorithms: [
        0xfafa, // GREASE sigalg (skipped; not part of JA4 either)
        // ML-DSA, offered since Chrome 154:
        0x0904, 0x0905, 0x0906,
        0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
    ],
    supportedVersions: [
        0x4a4a, // GREASE version (skipped)
        0x0304, 0x0303,
    ],
    alpnProtocols: ['h2', 'http/1.1'],
};

// Expected extension set (GREASE-filtered). Note that in reality order is randomized.
const CHROME_EXPECTED_EXTENSIONS = [
    0, 5, 10, 11, 13, 16, 18, 23, 27, 35, 43, 45, 51, 4832, 17613, 51764, 65037, 65281,
];

// Expected full JA4 fingerprint, as measured from real Chrome 155.0.8059.39
const CHROME_EXPECTED_JA4 = 't13d1518h2_8daaf6152771_4980c97edce0';

// Chrome JA3 matching the JA4 above. Note that since extension order and GREASE is 
// applied randomly, this is just a sample - there is no fixed Chrome JA3 nowadays.
const CHROME_EXPECTED_JA3 = '54e74f2b334705ff3e873478157eaa95';

describe('Chrome TLS fingerprint impersonation', () => {
    it('should match Chrome cipher suites exactly', async () => {
        const { tlsOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello(tlsOptions);

        expect(hello.ciphers).to.deep.equal([
            0x1301, 0x1302, 0x1303,
            0xc02b, 0xc02f, 0xc02c, 0xc030,
            0xcca9, 0xcca8,
            0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ]);
    });

    it('should match Chrome signature algorithms exactly', async () => {
        const { tlsOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello(tlsOptions);

        expect(hello.signatureAlgorithms).to.deep.equal([
            0x0904, 0x0905, 0x0906,
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ]);
    });

    it('should match Chrome supported groups exactly', async () => {
        const { tlsOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello(tlsOptions);

        expect(hello.groups).to.deep.equal([0x11ec, 0x001d, 0x0017, 0x0018]);
    });

    // Requires Node's bundled OpenSSL to be built with certificate compression
    // enabled (ext 27). First available in Node 26.4.0; earlier builds omit it.
    it('should match Chrome extensions exactly', expectedFailure('<24.19.0 <26.4.0', async () => {
        const { tlsOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello(tlsOptions);

        expect(new Set(hello.extensions)).to.deep.equal(new Set(CHROME_EXPECTED_EXTENSIONS));
        expect(hello.extensions).to.have.length(CHROME_EXPECTED_EXTENSIONS.length);
    }, () => {
        const { unsupported } = impersonate(chromeSpec);
        expect(unsupported.some(u => u.kind === 'extension' && u.id === 27)).to.be.true;
    }));

    // Requires OpenSSL EC point format fix (OpenSSL PR 26990)
    it('should send only uncompressed EC point format', expectedFailure('*', async () => {
        const { tlsOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello(tlsOptions);

        expect(hello.ecPointFormats).to.deep.equal([0]);
    }, () => {
        const { unsupported } = impersonate(chromeSpec);
        expect(unsupported.some(u => u.kind === 'extension' && u.id === 11)).to.be.true;
    }));

    // Depends on the correct extension set (certificate compression, Node 26.4.0+).
    // Unlike JA3, JA4 does not hash EC point formats, so it passes without OpenSSL PR 26990.
    it('should match Chrome JA4 fingerprint', expectedFailure('<24.19.0 <26.4.0', async () => {
        const { tlsOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello(tlsOptions);

        expect(hello.ja4).to.equal(CHROME_EXPECTED_JA4);
    }, () => {
        const { unsupported } = impersonate(chromeSpec);
        expect(unsupported.some(u => u.kind === 'extension' && u.id === 27)).to.be.true;
    }));

    it('should match Chrome JA3 fingerprint', expectedFailure('*', async () => {
        const { tlsOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello(tlsOptions);

        expect(hello.ja3).to.equal(CHROME_EXPECTED_JA3);
    }, () => {
        const { unsupported } = impersonate(chromeSpec);
        expect(unsupported.some(u => u.kind === 'extension' && u.id === 11)).to.be.true;
    }));

    runRealWorldTests('Chrome', chromeSpec);
});
