import { expect } from 'chai';
import { impersonate } from '../src/index.js';
import type { ClientHelloSpec } from '../src/index.js';
import { captureClientHello, expectedFailure, runRealWorldTests } from './test-helpers.js';

// Safari 26.0 (macOS Tahoe) ClientHello spec, derived from:
// https://github.com/lexiforest/curl-impersonate/blob/main/bin/curl_safari260
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
        // 3DES (legacy — Safari still sends these)
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
        { type: 27, data: Buffer.from([0x02, 0x00, 0x02]) }, // compress_certificate: brotli
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

// Expected extension set — note: Safari does NOT send session_ticket (35)
const SAFARI_EXPECTED_EXTENSIONS = [0, 23, 65281, 10, 11, 16, 5, 13, 18, 51, 45, 43, 27, 21];

// Expected JA3 hash (assumes correct ec_point_formats: [0] uncompressed only,
// and all 20 ciphers including 3DES)
const SAFARI_EXPECTED_JA3 = 'e6313618686ad203ec858e82dbbc1ae0';

// Expected full JA4 fingerprint (with all 20 ciphers including 3DES)
const SAFARI_EXPECTED_JA4 = 't13d2014h2_a09f3c656075_604f15001eed';

describe('Safari TLS fingerprint impersonation', () => {
    it('should match Safari cipher suites exactly (including 3DES)', expectedFailure('*', async () => {
        const { secureContext, connectOptions } = impersonate(safariSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.ciphers).to.deep.equal([
            0x1302, 0x1303, 0x1301,
            0xc02c, 0xc02b, 0xcca9,
            0xc030, 0xc02f, 0xcca8,
            0xc00a, 0xc009, 0xc014, 0xc013,
            0x009d, 0x009c, 0x0035, 0x002f,
            0xc008, 0xc012, 0x000a,
        ]);
    }));

    it('should match Safari signature algorithms exactly', async () => {
        const { secureContext, connectOptions } = impersonate(safariSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.signatureAlgorithms).to.deep.equal([
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
        ]);
    });

    it('should match Safari supported groups exactly', async () => {
        const { secureContext, connectOptions } = impersonate(safariSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.groups).to.deep.equal([0x11ec, 0x001d, 0x0017, 0x0018, 0x0019]);
    });

    it('should match Safari extensions exactly', expectedFailure('*', async () => {
        const { secureContext, connectOptions } = impersonate(safariSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });
        const extSet = new Set(hello.extensions);

        expect(extSet).to.deep.equal(new Set(SAFARI_EXPECTED_EXTENSIONS));
        expect(hello.extensions).to.have.length(SAFARI_EXPECTED_EXTENSIONS.length);
        expect(extSet.has(35), 'session_ticket (35) should be absent').to.be.false;
    }));

    it('should send only uncompressed EC point format', expectedFailure('*', async () => {
        const { secureContext, connectOptions } = impersonate(safariSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.ecPointFormats).to.deep.equal([0]);
    }));

    it('should match Safari JA4 fingerprint', expectedFailure('*', async () => {
        const { secureContext, connectOptions } = impersonate(safariSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.ja4).to.equal(SAFARI_EXPECTED_JA4);
    }));

    it('should match Safari JA3 fingerprint', expectedFailure('*', async () => {
        const { secureContext, connectOptions } = impersonate(safariSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.ja3).to.equal(SAFARI_EXPECTED_JA3);
    }));

    runRealWorldTests('Safari', safariSpec);
});
