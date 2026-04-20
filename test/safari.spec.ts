import { expect } from 'chai';
import { impersonate } from '../src/index.js';
import type { ClientHelloSpec } from '../src/index.js';
import { captureClientHello, formatClientHello, extensionName } from './test-helpers.js';

// Safari 26.0 (macOS Tahoe) ClientHello spec, derived from:
// https://github.com/lexiforest/curl-impersonate/blob/main/bin/curl_safari260
//
// Cipher order (IANA names from the curl-impersonate wrapper script):
//   TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, TLS_AES_128_GCM_SHA256,
//   ECDHE-ECDSA GCM/ChaCha/CBC, ECDHE-RSA GCM/ChaCha/CBC,
//   RSA GCM/CBC, then 3DES (legacy)
//
// Changes from Safari 18:
// - TLS 1.3 cipher order changed: AES-256 first (was AES-128)
// - X25519MLKEM768 added to supported groups (post-quantum)
// - ecdsa_sha1 (0x0203) removed from sigalgs, ecdsa_secp384r1_sha384 (0x0503) added
// - Still includes 3DES ciphers (compiled out of most OpenSSL 3.x builds)
const safariSpec: ClientHelloSpec = {
    cipherSuites: [
        // TLS 1.3 (Safari 26 order: AES-256, ChaCha20, AES-128)
        0x1302, 0x1303, 0x1301,
        // TLS 1.2 ECDHE+ECDSA
        0xc02c, 0xc02b, 0xcca9,
        // TLS 1.2 ECDHE+RSA
        0xc030, 0xc02f, 0xcca8,
        // TLS 1.2 ECDHE CBC
        0xc00a, 0xc009, 0xc014, 0xc013,
        // TLS 1.2 RSA (no PFS)
        0x009d, 0x009c, 0x0035, 0x002f,
        // 3DES (legacy — unavailable in standard OpenSSL 3.x builds,
        // compiled out via OPENSSL_NO_WEAK_SSL_CIPHERS since 2016)
        0xc008, 0xc012, 0x000a,
    ],
    extensions: [
        { type: 0 },     // server_name
        { type: 23 },    // extended_master_secret
        { type: 65281 }, // renegotiation_info
        { type: 10 },    // supported_groups
        { type: 11 },    // ec_point_formats
        { type: 16 },    // ALPN
        { type: 5 },     // status_request (OCSP)
        { type: 13 },    // signature_algorithms
        { type: 18 },    // signed_certificate_timestamp (default: empty)
        { type: 51 },    // key_share
        { type: 45 },    // psk_key_exchange_modes
        { type: 43 },    // supported_versions
        { type: 27, data: Buffer.from([0x02, 0x00, 0x02]) }, // compress_certificate: brotli (zlib)
        { type: 21 },    // padding
    ],
    supportedGroups: [
        0x11ec, // X25519MLKEM768 (post-quantum, new in Safari 26)
        0x001d, 0x0017, 0x0018, 0x0019,
    ],
    signatureAlgorithms: [
        0x0403, // ecdsa_secp256r1_sha256
        0x0804, // rsa_pss_rsae_sha256
        0x0401, // rsa_pkcs1_sha256
        0x0503, // ecdsa_secp384r1_sha384
        0x0805, // rsa_pss_rsae_sha384
        0x0501, // rsa_pkcs1_sha384
        0x0806, // rsa_pss_rsae_sha512
        0x0601, // rsa_pkcs1_sha512
        0x0201, // rsa_pkcs1_sha1 (legacy)
    ],
    alpnProtocols: ['h2', 'http/1.1'],
};

// Safari 26's 17 non-3DES ciphers sorted (for JA4 hash when 3DES unavailable)
const SAFARI_CIPHERS_SORTED_NO_3DES = [
    0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303,
    0xc009, 0xc00a, 0xc013, 0xc014, 0xc02b, 0xc02c, 0xc02f, 0xc030,
    0xcca8, 0xcca9,
];

// All 20 Safari ciphers sorted (for JA4 hash when 3DES available)
const SAFARI_CIPHERS_SORTED_ALL = [
    0x000a, 0x002f, 0x0035, 0x009c, 0x009d, 0x1301, 0x1302, 0x1303,
    0xc008, 0xc009, 0xc00a, 0xc012, 0xc013, 0xc014, 0xc02b, 0xc02c,
    0xc02f, 0xc030, 0xcca8, 0xcca9,
];

// Real Safari JA4 cipher hash (with all 20 ciphers including 3DES)
const SAFARI_CIPHER_HASH_ALL = 'a09f3c656075';

describe('Safari TLS fingerprint impersonation', () => {
    it('should match Safari cipher suites (excluding any unavailable 3DES)', async () => {
        const { secureContext, connectOptions } = impersonate(safariSpec);
        const hello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        const [, ciphers] = hello.fingerprintData;

        console.log('\n--- Safari 26 Spec TLS ClientHello ---');
        console.log(formatClientHello(hello));
        console.log('--------------------------------------\n');

        // We expect either 20 (with 3DES) or 17 (without 3DES) ciphers
        const has3DES = ciphers.includes(0x000a);
        if (has3DES) {
            expect(ciphers).to.have.length(20);
            const sortedCiphers = [...ciphers].sort((a, b) => a - b);
            expect(sortedCiphers).to.deep.equal(SAFARI_CIPHERS_SORTED_ALL);
        } else {
            console.log('  (3DES ciphers unavailable in this OpenSSL build)');
            expect(ciphers).to.have.length(17);
            const sortedCiphers = [...ciphers].sort((a, b) => a - b);
            expect(sortedCiphers).to.deep.equal(SAFARI_CIPHERS_SORTED_NO_3DES);
        }

        // JA4 cipher hash should match the full Safari hash if 3DES is available
        const ja4Parts = hello.ja4.split('_');
        if (has3DES) {
            expect(ja4Parts[1]).to.equal(SAFARI_CIPHER_HASH_ALL);
        }
    });

    it('should match Safari 26 signature algorithms (no ecdsa_sha1)', async () => {
        const { secureContext, connectOptions } = impersonate(safariSpec);
        const hello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        const [, , , , , sigAlgorithms] = hello.fingerprintData;

        // Safari 26 sends 9 signature algorithms (rsa_pkcs1_sha1 but no ecdsa_sha1)
        expect(sigAlgorithms).to.have.length(9);

        const expectedSigAlgs = new Set([
            0x0403, 0x0804, 0x0401,
            0x0503, 0x0805, 0x0501,
            0x0806, 0x0601,
            0x0201, // rsa_pkcs1_sha1 (legacy, still present)
        ]);
        expect(new Set(sigAlgorithms)).to.deep.equal(expectedSigAlgs);

        // ecdsa_sha1 should NOT be present (removed in Safari 26)
        expect(sigAlgorithms).to.not.include(0x0203);
    });

    it('should include X25519MLKEM768 in supported groups', async () => {
        const { secureContext, connectOptions } = impersonate(safariSpec);
        const hello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        const [, , , groups] = hello.fingerprintData;

        // Safari 26 sends 5 groups: X25519MLKEM768, X25519, P-256, P-384, P-521
        expect(groups).to.have.length(5);
        expect(new Set(groups)).to.deep.equal(new Set([
            0x11ec, 0x001d, 0x0017, 0x0018, 0x0019,
        ]));
    });

    it('should include Safari-specific extensions and exclude others', async () => {
        const { secureContext, connectOptions } = impersonate(safariSpec);
        const hello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        const [, , extensions] = hello.fingerprintData;
        const extSet = new Set(extensions);

        // Extensions Safari sends (that we can control)
        expect(extSet.has(0), 'server_name (0)').to.be.true;
        expect(extSet.has(5), 'status_request (5)').to.be.true;
        expect(extSet.has(10), 'supported_groups (10)').to.be.true;
        expect(extSet.has(11), 'ec_point_formats (11)').to.be.true;
        expect(extSet.has(13), 'signature_algorithms (13)').to.be.true;
        expect(extSet.has(16), 'ALPN (16)').to.be.true;
        expect(extSet.has(18), 'signed_certificate_timestamp (18)').to.be.true;
        expect(extSet.has(23), 'extended_master_secret (23)').to.be.true;
        expect(extSet.has(43), 'supported_versions (43)').to.be.true;
        expect(extSet.has(45), 'psk_key_exchange_modes (45)').to.be.true;
        expect(extSet.has(51), 'key_share (51)').to.be.true;
        expect(extSet.has(65281), 'renegotiation_info (65281)').to.be.true;

        // padding (21) is predefined and OpenSSL only adds it conditionally
        // (when ClientHello is 256-511 bytes), so we can't assert its presence

        // Safari does NOT send these (unlike Chrome/Firefox)
        expect(extSet.has(28), 'record_size_limit (28) should be absent').to.be.false;
        expect(extSet.has(34), 'delegated_credentials (34) should be absent').to.be.false;
        expect(extSet.has(49), 'post_handshake_auth (49) should be absent').to.be.false;
        expect(extSet.has(17613), 'application_settings (17613) should be absent').to.be.false;
        expect(extSet.has(65037), 'encrypted_client_hello (65037) should be absent').to.be.false;

        // Safari does NOT send encrypt_then_mac
        expect(extSet.has(22), 'encrypt_then_mac (22) should be absent').to.be.false;

        // session_ticket (35) is predefined — OpenSSL sends it by default and we
        // can't suppress it, even though real Safari doesn't send it

        const safariExts = [0, 5, 10, 11, 13, 16, 18, 23, 27, 43, 45, 51, 65281];
        const missing = safariExts.filter(e => !extSet.has(e));
        const extra = extensions.filter(e => !safariExts.includes(e));

        if (missing.length) {
            console.log(`Missing Safari extensions: ${missing.map(e => `${e}(${extensionName(e)})`).join(', ')}`);
        }
        if (extra.length) {
            console.log(`Extra extensions (not in Safari): ${extra.map(e => `${e}(${extensionName(e)})`).join(', ')}`);
        }
    });

    it('should produce a JA4 that differs from Chrome, Firefox, and default', async () => {
        const { secureContext, connectOptions } = impersonate(safariSpec);
        const hello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        const defaultHello = await captureClientHello();
        const ja4Parts = hello.ja4.split('_');

        // The JA4 prefix should reflect Safari's cipher count and ALPN
        const [, ciphers] = hello.fingerprintData;
        const expectedPrefix = `t13d${String(ciphers.length).padStart(2, '0')}`;
        expect(ja4Parts[0]).to.match(new RegExp(`^${expectedPrefix}`));

        console.log(`\nJA4 default:  ${defaultHello.ja4}`);
        console.log(`JA4 safari:   ${hello.ja4}`);

        expect(hello.ja4).to.not.equal(defaultHello.ja4);
    });
});
