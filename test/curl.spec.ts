import { expect } from 'chai';
import { impersonate } from '../src/index.js';
import type { ClientHelloSpec } from '../src/index.js';
import { captureClientHello, runRealWorldTests } from './test-helpers.js';

// Curl 8.5 / OpenSSL 3.0.13 default ClientHello parameters
const curlSpec: ClientHelloSpec = {
    cipherSuites: [
        // TLS 1.3
        0x1302, 0x1303, 0x1301,
        // TLS 1.2 — OpenSSL 3.0.13 default order
        0xc02c, 0xc030, 0x009f, 0xcca9, 0xcca8, 0xccaa,
        0xc02b, 0xc02f, 0x009e,
        0xc024, 0xc028, 0x006b, 0xc023, 0xc027, 0x0067,
        0xc00a, 0xc014, 0x0039, 0xc009, 0xc013, 0x0033,
        0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f,
        0x00ff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
    ],
    extensions: [
        { type: 0 },     // server_name
        { type: 11 },    // ec_point_formats
        { type: 10 },    // supported_groups
        { type: 16 },    // ALPN
        { type: 22 },    // encrypt_then_mac
        { type: 23 },    // extended_master_secret
        { type: 49 },    // post_handshake_auth
        { type: 13 },    // signature_algorithms
        { type: 43 },    // supported_versions
        { type: 45 },    // psk_key_exchange_modes
        { type: 51 },    // key_share
        { type: 21 },    // padding
    ],
    supportedGroups: [
        0x001d, 0x0017, 0x001e, 0x0019, 0x0018,
        0x0100, 0x0101, 0x0102, 0x0103, 0x0104,
    ],
    signatureAlgorithms: [
        0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
        0x0809, 0x080a, 0x080b,
        0x0804, 0x0805, 0x0806,
        0x0401, 0x0501, 0x0601,
        0x0303, 0x0301, 0x0302,
        0x0402, 0x0502, 0x0602,
    ],
    // curl links OpenSSL, which advertises all three EC point formats - the
    // same set Node's OpenSSL sends, so this reproduces exactly (unlike the
    // BoringSSL/NSS clients that send only [0]). This is why curl's JA3 matches.
    ecPointFormats: [0, 1, 2],
    alpnProtocols: ['h2', 'http/1.1'],
};

const CURL_EXPECTED_JA3 = '0149f47eabf9a20d0893e2a44e5a6323';
const CURL_EXPECTED_JA4 = 't13d3112h2_e8f1e7e78f70_b26ce05bbdd6';

// Curl's hello carries the renegotiation SCSV, which OpenSSL only emits at
// security level 0, so full-fidelity reproduction requires 'insecure' mode.
describe('Curl TLS fingerprint impersonation', () => {
    it('should match curl cipher suites exactly', async () => {
        const { tlsOptions } = impersonate(curlSpec, { security: 'insecure' });
        const hello = await captureClientHello(tlsOptions);

        expect(hello.ciphers).to.deep.equal([
            0x1302, 0x1303, 0x1301,
            0xc02c, 0xc030, 0x009f, 0xcca9, 0xcca8, 0xccaa,
            0xc02b, 0xc02f, 0x009e,
            0xc024, 0xc028, 0x006b, 0xc023, 0xc027, 0x0067,
            0xc00a, 0xc014, 0x0039, 0xc009, 0xc013, 0x0033,
            0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f,
            0x00ff,
        ]);
    });

    it('should match curl signature algorithms exactly', async () => {
        const { tlsOptions } = impersonate(curlSpec, { security: 'insecure' });
        const hello = await captureClientHello(tlsOptions);

        expect(hello.signatureAlgorithms).to.deep.equal([
            0x0403, 0x0503, 0x0603, 0x0807, 0x0808,
            0x0809, 0x080a, 0x080b,
            0x0804, 0x0805, 0x0806,
            0x0401, 0x0501, 0x0601,
            0x0303, 0x0301, 0x0302,
            0x0402, 0x0502, 0x0602,
        ]);
    });

    it('should match curl supported groups exactly', async () => {
        const { tlsOptions } = impersonate(curlSpec, { security: 'insecure' });
        const hello = await captureClientHello(tlsOptions);

        expect(hello.groups).to.deep.equal([
            0x001d, 0x0017, 0x001e, 0x0019, 0x0018,
            0x0100, 0x0101, 0x0102, 0x0103, 0x0104,
        ]);
    });

    it('should match curl extensions exactly', async () => {
        const { tlsOptions } = impersonate(curlSpec, { security: 'insecure' });
        const hello = await captureClientHello(tlsOptions);

        expect(new Set(hello.extensions)).to.deep.equal(new Set(
            [0, 11, 10, 16, 22, 23, 49, 13, 43, 45, 51, 21]
        ));
        expect(hello.extensions).to.have.length(12);
    });

    it('should match curl JA4 fingerprint', async () => {
        const { tlsOptions } = impersonate(curlSpec, { security: 'insecure' });
        const hello = await captureClientHello(tlsOptions);

        expect(hello.ja4).to.equal(CURL_EXPECTED_JA4);
    });

    // curl requests [0,1,2], exactly what OpenSSL < 3.6 sends, so its JA3 matches
    // today (unlike the [0]-only clients). If OpenSSL 3.6 switches to [0] this
    // will start failing - the intended alert to add ec_point handling for curl.
    it('should match curl JA3 fingerprint', async () => {
        const { tlsOptions } = impersonate(curlSpec, { security: 'insecure' });
        const hello = await captureClientHello(tlsOptions);

        expect(hello.ja3).to.equal(CURL_EXPECTED_JA3);
    });

    runRealWorldTests('Curl', curlSpec);
});
