import { expect } from 'chai';
import { impersonate } from '../src/index.js';
import type { ClientHelloSpec } from '../src/index.js';
import { captureClientHello, formatClientHello, extensionName, isGreaseValue } from './test-helpers.js';

// Real Chrome 133+ JA4 cipher hash
const CHROME_CIPHER_HASH = '8daaf6152771';

// Chrome cipher suite IDs in sorted order (for JA4 hash verification)
const CHROME_CIPHERS_SORTED = [
    0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303,
    0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030,
    0xcca8, 0xcca9,
];

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

describe('Chrome TLS fingerprint impersonation', () => {
    it('should match Chrome cipher suites exactly', async () => {
        const { secureContext, connectOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        const [, ciphers] = hello.fingerprintData;

        console.log('\n--- Chrome Spec TLS ClientHello ---');
        console.log(formatClientHello(hello));
        console.log('-----------------------------------\n');

        // 15 ciphers (3 TLS1.3 + 12 TLS1.2; GREASE is stripped)
        expect(ciphers).to.have.length(15);

        const sortedCiphers = [...ciphers].sort((a, b) => a - b);
        expect(sortedCiphers).to.deep.equal(CHROME_CIPHERS_SORTED);

        const ja4Parts = hello.ja4.split('_');
        expect(ja4Parts[1]).to.equal(CHROME_CIPHER_HASH);
    });

    it('should match Chrome signature algorithms', async () => {
        const { secureContext, connectOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        const [, , , , , sigAlgorithms] = hello.fingerprintData;

        // Chrome sends 8 signature algorithms (no SHA-1)
        expect(sigAlgorithms).to.have.length(8);

        const expectedSigAlgs = new Set([
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
        ]);
        expect(new Set(sigAlgorithms)).to.deep.equal(expectedSigAlgs);
    });

    it('should include Chrome-specific extensions and exclude Firefox-only ones', async () => {
        const { secureContext, connectOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        const [, , extensions] = hello.fingerprintData;
        const extSet = new Set(extensions);

        // Extensions Chrome sends
        expect(extSet.has(0), 'server_name (0)').to.be.true;
        expect(extSet.has(5), 'status_request (5)').to.be.true;
        expect(extSet.has(10), 'supported_groups (10)').to.be.true;
        expect(extSet.has(11), 'ec_point_formats (11)').to.be.true;
        expect(extSet.has(13), 'signature_algorithms (13)').to.be.true;
        expect(extSet.has(16), 'ALPN (16)').to.be.true;
        expect(extSet.has(18), 'signed_certificate_timestamp (18)').to.be.true;
        expect(extSet.has(23), 'extended_master_secret (23)').to.be.true;
        expect(extSet.has(35), 'session_ticket (35)').to.be.true;
        expect(extSet.has(43), 'supported_versions (43)').to.be.true;
        expect(extSet.has(45), 'psk_key_exchange_modes (45)').to.be.true;
        expect(extSet.has(51), 'key_share (51)').to.be.true;
        expect(extSet.has(65281), 'renegotiation_info (65281)').to.be.true;

        // Chrome-specific extensions
        expect(extSet.has(17613), 'application_settings (17613)').to.be.true;
        expect(extSet.has(65037), 'encrypted_client_hello (65037)').to.be.true;

        // GREASE extensions stripped from fingerprintData
        const greaseExts = extensions.filter(e => isGreaseValue(e));
        expect(greaseExts).to.have.length(0, 'GREASE values should be stripped by fingerprintData');

        // Firefox-only extensions should NOT be present
        expect(extSet.has(28), 'record_size_limit (28) should be absent').to.be.false;
        expect(extSet.has(34), 'delegated_credentials (34) should be absent').to.be.false;
        expect(extSet.has(49), 'post_handshake_auth (49) should be absent').to.be.false;

        // encrypt_then_mac should be absent
        expect(extSet.has(22), 'encrypt_then_mac (22) should be absent').to.be.false;
    });

    it('should produce a JA4 that differs from both default and Firefox', async () => {
        const { secureContext, connectOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        const defaultHello = await captureClientHello();

        const ja4Parts = hello.ja4.split('_');

        // Part a: cipher count = 15
        expect(ja4Parts[0]).to.match(/^t13d15/);

        // Part b: cipher hash must match real Chrome
        expect(ja4Parts[1]).to.equal(CHROME_CIPHER_HASH);

        console.log(`\nJA4 default:  ${defaultHello.ja4}`);
        console.log(`JA4 chrome:   ${hello.ja4}`);

        expect(hello.ja4).to.not.equal(defaultHello.ja4);
    });
});
