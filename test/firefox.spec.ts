import { expect } from 'chai';
import { impersonate } from '../src/index.js';
import type { ClientHelloSpec } from '../src/index.js';
import { captureClientHello, formatClientHello, extensionName } from './test-helpers.js';

// Real Firefox 133+ JA4 cipher hash (stable across Firefox 115-144+)
const FIREFOX_CIPHER_HASH = '5b57614c22b0';

// Real Firefox cipher suite IDs in sorted order (for JA4 hash verification)
const FIREFOX_CIPHERS_SORTED = [
    0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303,
    0xc009, 0xc00a, 0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030,
    0xcca8, 0xcca9,
];

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

describe('Firefox TLS fingerprint impersonation', () => {
    it('should match Firefox cipher suites exactly', async () => {
        const { secureContext, connectOptions } = impersonate(firefoxSpec);
        const hello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        const [, ciphers] = hello.fingerprintData;

        console.log('\n--- Firefox Spec TLS ClientHello ---');
        console.log(formatClientHello(hello));
        console.log('------------------------------------\n');

        expect(ciphers).to.have.length(17);

        const sortedCiphers = [...ciphers].sort((a, b) => a - b);
        expect(sortedCiphers).to.deep.equal(FIREFOX_CIPHERS_SORTED);

        const ja4Parts = hello.ja4.split('_');
        expect(ja4Parts[1]).to.equal(FIREFOX_CIPHER_HASH);
    });

    it('should match Firefox signature algorithms', async () => {
        const { secureContext, connectOptions } = impersonate(firefoxSpec);
        const hello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        const [, , , , , sigAlgorithms] = hello.fingerprintData;

        expect(sigAlgorithms).to.have.length(11);

        const expectedSigAlgs = new Set([
            0x0403, 0x0503, 0x0603,
            0x0804, 0x0805, 0x0806,
            0x0401, 0x0501, 0x0601,
            0x0203, 0x0201,
        ]);
        expect(new Set(sigAlgorithms)).to.deep.equal(expectedSigAlgs);
    });

    it('should include Firefox-specific extensions', async () => {
        const { secureContext, connectOptions } = impersonate(firefoxSpec);
        const hello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        const [, , extensions] = hello.fingerprintData;
        const extSet = new Set(extensions);

        // Extensions that Firefox sends
        expect(extSet.has(0), 'server_name (0)').to.be.true;
        expect(extSet.has(5), 'status_request (5)').to.be.true;
        expect(extSet.has(10), 'supported_groups (10)').to.be.true;
        expect(extSet.has(11), 'ec_point_formats (11)').to.be.true;
        expect(extSet.has(13), 'signature_algorithms (13)').to.be.true;
        expect(extSet.has(16), 'ALPN (16)').to.be.true;
        expect(extSet.has(18), 'signed_certificate_timestamp (18)').to.be.true;
        expect(extSet.has(23), 'extended_master_secret (23)').to.be.true;
        expect(extSet.has(28), 'record_size_limit (28)').to.be.true;
        expect(extSet.has(34), 'delegated_credentials (34)').to.be.true;
        expect(extSet.has(35), 'session_ticket (35)').to.be.true;
        expect(extSet.has(43), 'supported_versions (43)').to.be.true;
        expect(extSet.has(45), 'psk_key_exchange_modes (45)').to.be.true;
        expect(extSet.has(49), 'post_handshake_auth (49)').to.be.true;
        expect(extSet.has(51), 'key_share (51)').to.be.true;
        expect(extSet.has(65037), 'encrypted_client_hello (65037)').to.be.true;
        expect(extSet.has(65281), 'renegotiation_info (65281)').to.be.true;

        // Firefox does NOT send encrypt_then_mac
        expect(extSet.has(22), 'encrypt_then_mac (22) should be absent').to.be.false;

        const firefoxExts = [0, 5, 10, 11, 13, 16, 18, 23, 27, 28, 34, 35, 43, 45, 49, 51, 65037, 65281];
        const missing = firefoxExts.filter(e => !extSet.has(e));
        const extra = extensions.filter(e => !firefoxExts.includes(e));

        if (missing.length) {
            console.log(`Missing Firefox extensions: ${missing.map(e => `${e}(${extensionName(e)})`).join(', ')}`);
        }
        if (extra.length) {
            console.log(`Extra extensions (not in Firefox): ${extra.map(e => `${e}(${extensionName(e)})`).join(', ')}`);
        }
    });

    it('should produce a JA4 close to real Firefox', async () => {
        const { secureContext, connectOptions } = impersonate(firefoxSpec);
        const hello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        const defaultHello = await captureClientHello();
        const ja4Parts = hello.ja4.split('_');

        // Part a: t13dXXh2 where XX starts with 17 (cipher count)
        expect(ja4Parts[0]).to.match(/^t13d17/);

        // Part b: cipher hash must match real Firefox
        expect(ja4Parts[1]).to.equal(FIREFOX_CIPHER_HASH);

        console.log(`\nJA4 default:  ${defaultHello.ja4}`);
        console.log(`JA4 firefox:  ${hello.ja4}`);

        expect(hello.ja4).to.not.equal(defaultHello.ja4);
    });
});
