import { expect } from 'chai';
import { impersonate } from '../src/index.js';
import type { ClientHelloSpec } from '../src/index.js';
import { captureClientHello, expectedFailure, runRealWorldTests } from './test-helpers.js';

// OkHttp 4.x on Android (Conscrypt/BoringSSL) for a fresh connection with default ALPN
const okhttpSpec: ClientHelloSpec = {
    cipherSuites: [
        // TLS 1.3 (Conscrypt order: AES-128, AES-256, ChaCha20)
        0x1301, 0x1302, 0x1303,
        // TLS 1.2 ECDHE+ECDSA
        0xc02b, 0xc02c, 0xcca9,
        // TLS 1.2 ECDHE+RSA
        0xc02f, 0xc030, 0xcca8,
        // TLS 1.2 ECDHE+RSA CBC
        0xc013, 0xc014,
        // TLS 1.2 RSA
        0x009c, 0x009d, 0x002f, 0x0035,
    ],
    extensions: [
        { type: 0 },     // server_name
        { type: 23 },    // extended_master_secret
        { type: 65281 }, // renegotiation_info
        { type: 10 },    // supported_groups
        { type: 11 },    // ec_point_formats
        { type: 5 },     // status_request
        { type: 16 },    // ALPN
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
    alpnProtocols: ['h2', 'http/1.1'],
};

const OKHTTP_EXPECTED_JA3 = '03be3bff8d3d1c3c2a22b850f9540f9f';
const OKHTTP_EXPECTED_JA4 = 't13d1511h2_8daaf6152771_86dd91ae2a36';

describe('OkHttp/Android TLS fingerprint impersonation', () => {
    it('should match OkHttp cipher suites exactly', async () => {
        const { tlsOptions } = impersonate(okhttpSpec);
        const hello = await captureClientHello(tlsOptions);

        expect(hello.ciphers).to.deep.equal([
            0x1301, 0x1302, 0x1303,
            0xc02b, 0xc02c, 0xcca9,
            0xc02f, 0xc030, 0xcca8,
            0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ]);
    });

    it('should match OkHttp signature algorithms exactly', async () => {
        const { tlsOptions } = impersonate(okhttpSpec);
        const hello = await captureClientHello(tlsOptions);

        expect(hello.signatureAlgorithms).to.deep.equal([
            0x0403, 0x0804, 0x0401,
            0x0503, 0x0805, 0x0501,
            0x0806, 0x0601,
            0x0201,
        ]);
    });

    it('should match OkHttp supported groups exactly', async () => {
        const { tlsOptions } = impersonate(okhttpSpec);
        const hello = await captureClientHello(tlsOptions);

        expect(hello.groups).to.deep.equal([0x001d, 0x0017, 0x0018]);
    });

    it('should match OkHttp extensions exactly', async () => {
        const { tlsOptions } = impersonate(okhttpSpec);
        const hello = await captureClientHello(tlsOptions);

        expect(new Set(hello.extensions)).to.deep.equal(new Set(
            [0, 23, 65281, 10, 11, 5, 16, 13, 51, 45, 43]
        ));
        expect(hello.extensions).to.have.length(11);
    });

    // Requires OpenSSL EC point format fix (OpenSSL PR 26990)
    it('should send only uncompressed EC point format', expectedFailure('*', async () => {
        const { tlsOptions } = impersonate(okhttpSpec);
        const hello = await captureClientHello(tlsOptions);

        expect(hello.ecPointFormats).to.deep.equal([0]);
    }, () => {
        const { unsupported } = impersonate(okhttpSpec);
        expect(unsupported.some(u => u.kind === 'extension' && u.id === 11)).to.be.true;
    }));

    it('should match OkHttp JA4 fingerprint', async () => {
        const { tlsOptions } = impersonate(okhttpSpec);
        const hello = await captureClientHello(tlsOptions);

        expect(hello.ja4).to.equal(OKHTTP_EXPECTED_JA4);
    });

    // JA3 includes EC point formats, so depends on OpenSSL PR 26990
    it('should match OkHttp JA3 fingerprint', expectedFailure('*', async () => {
        const { tlsOptions } = impersonate(okhttpSpec);
        const hello = await captureClientHello(tlsOptions);

        expect(hello.ja3).to.equal(OKHTTP_EXPECTED_JA3);
    }, () => {
        const { unsupported } = impersonate(okhttpSpec);
        expect(unsupported.some(u => u.kind === 'extension' && u.id === 11)).to.be.true;
    }));

    runRealWorldTests('OkHttp', okhttpSpec);
});
