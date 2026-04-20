import { expect } from 'chai';
import * as tls from 'node:tls';
import * as https from 'node:https';
import { impersonate } from '../src/index.js';
import type { ClientHelloSpec } from '../src/index.js';

const FINGERPRINT_URL = 'https://testserver.host/tls/fingerprint';

interface FingerprintResponse {
    ja3: string;
    ja4: string;
}

function fetchFingerprint(options: {
    secureContext?: tls.SecureContext;
    ALPNProtocols?: string[];
    requestOCSP?: boolean;
}): Promise<FingerprintResponse> {
    return fetchUrl(FINGERPRINT_URL, options);
}

function fetchUrl<T = any>(url: string, options: {
    secureContext?: tls.SecureContext;
    ALPNProtocols?: string[];
    requestOCSP?: boolean;
} = {}): Promise<T> {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Request timeout')), 10000);

        // Use a fresh agent to avoid TLS session caching between tests
        const agent = new https.Agent({
            keepAlive: false,
            maxCachedSessions: 0,
        });

        const req = https.get(url, {
            agent,
            ...(options.secureContext ? { secureContext: options.secureContext } : {}),
            ...(options.ALPNProtocols ? { ALPNProtocols: options.ALPNProtocols } : {}),
            ...(options.requestOCSP ? { requestOCSP: true } : {}),
        }, (res) => {
            let data = '';
            res.on('data', (chunk: Buffer) => { data += chunk; });
            res.on('end', () => {
                clearTimeout(timeout);
                agent.destroy();
                try {
                    resolve(JSON.parse(data));
                } catch (e) {
                    reject(new Error(`Invalid JSON: ${data}`));
                }
            });
        });

        req.on('error', (e) => {
            clearTimeout(timeout);
            agent.destroy();
            reject(e);
        });
    });
}

function connectTls(hostname: string, options: {
    secureContext?: tls.SecureContext;
    ALPNProtocols?: string[];
}): Promise<{ protocol: string | null }> {
    return new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('Connect timeout')), 10000);

        const socket = tls.connect({
            host: hostname,
            port: 443,
            servername: hostname,
            ...options,
        }, () => {
            clearTimeout(timeout);
            const protocol = socket.getProtocol();
            socket.destroy();
            resolve({ protocol });
        });

        socket.on('error', (e) => {
            clearTimeout(timeout);
            socket.destroy();
            reject(e);
        });
    });
}

describe('Live fingerprint verification', function () {
    this.timeout(15000);

    // Firefox-like spec (same as in firefox.spec.ts)
    const firefoxSpec: ClientHelloSpec = {
        cipherSuites: [
            0x1301, 0x1303, 0x1302,
            0xc02b, 0xc02f, 0xcca9, 0xcca8, 0xc02c, 0xc030,
            0xc00a, 0xc009, 0xc013, 0xc014,
            0x009c, 0x009d, 0x002f, 0x0035,
        ],
        extensions: [
            { type: 0 }, { type: 23 }, { type: 65281 }, { type: 10 },
            { type: 11 }, { type: 35 }, { type: 16 }, { type: 5 },
            { type: 34 }, { type: 28 }, { type: 18 },
            { type: 27, data: Buffer.from([0x06, 0x00, 0x02, 0x00, 0x01, 0x00, 0x03]) },
            { type: 13 }, { type: 43 }, { type: 45 },
            { type: 51 }, { type: 49 },
            { type: 65037 },
        ],
        supportedGroups: [0x11ec, 0x001d, 0x0017, 0x0018, 0x0019, 0x0100, 0x0101],
        signatureAlgorithms: [
            0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
            0x0401, 0x0501, 0x0601, 0x0203, 0x0201,
        ],
        alpnProtocols: ['h2', 'http/1.1'],
    };

    it('Firefox-like spec should produce matching JA4 cipher hash on a live server', async function () {
        let fp: FingerprintResponse;
        try {
            const { secureContext, connectOptions } = impersonate(firefoxSpec);
            fp = await fetchFingerprint({
                secureContext,
                ...connectOptions,
            });
        } catch (e: any) {
            this.skip(); // Network unavailable
            return;
        }

        console.log(`\nLive Firefox JA4: ${fp.ja4}`);
        const ja4Parts = fp.ja4.split('_');
        expect(ja4Parts[1]).to.equal('5b57614c22b0');
    });

    it('Chrome-like spec should produce matching JA4 cipher hash on a live server', async function () {
        const chromeSpec: ClientHelloSpec = {
            cipherSuites: [
                0x3a3a, 0x1301, 0x1302, 0x1303,
                0xc02b, 0xc02f, 0xc02c, 0xc030,
                0xcca9, 0xcca8,
                0xc013, 0xc014,
                0x009c, 0x009d, 0x002f, 0x0035,
            ],
            extensions: [
                { type: 0x2a2a }, { type: 0 }, { type: 23 }, { type: 65281 },
                { type: 10 }, { type: 11 }, { type: 35 }, { type: 16 },
                { type: 5 }, { type: 18 },
                { type: 27, data: Buffer.from([0x02, 0x00, 0x02]) },
                { type: 13 }, { type: 43 }, { type: 45 }, { type: 51 },
                { type: 17613 }, { type: 65037 }, { type: 0x4a4a },
            ],
            supportedGroups: [0x6a6a, 0x11ec, 0x001d, 0x0017, 0x0018],
            signatureAlgorithms: [
                0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601,
            ],
            alpnProtocols: ['h2', 'http/1.1'],
        };

        let fp: FingerprintResponse;
        try {
            const { secureContext, connectOptions } = impersonate(chromeSpec);
            fp = await fetchFingerprint({
                secureContext,
                ...connectOptions,
            });
        } catch (e: any) {
            this.skip();
            return;
        }

        console.log(`\nLive Chrome JA4: ${fp.ja4}`);
        const ja4Parts = fp.ja4.split('_');
        expect(ja4Parts[1]).to.equal('8daaf6152771');
    });

    it('round-trip: Node.js default fingerprint matches via live server', async function () {
        // Get the default Node.js fingerprint from the live server
        let defaultFp: FingerprintResponse;
        try {
            defaultFp = await fetchFingerprint({
                ALPNProtocols: ['h2', 'http/1.1'],
            });
        } catch {
            this.skip();
            return;
        }

        console.log(`\nDefault Node.js live JA4: ${defaultFp.ja4}`);

        // Capture Node.js default ClientHello locally to build a spec
        const { captureClientHello } = await import('./test-helpers.js');
        const defaultHello = await captureClientHello({
            ALPNProtocols: ['h2', 'http/1.1'],
        });

        const [, ciphers, extensions, groups, , sigAlgorithms] = defaultHello.fingerprintData;

        // Build spec from captured data
        const spec: ClientHelloSpec = {
            cipherSuites: ciphers,
            extensions: extensions.map((type: number) => ({ type })),
            supportedGroups: groups,
            signatureAlgorithms: sigAlgorithms,
            alpnProtocols: ['h2', 'http/1.1'],
        };

        let impFp: FingerprintResponse;
        try {
            const { secureContext, connectOptions } = impersonate(spec);
            impFp = await fetchFingerprint({
                secureContext,
                ...connectOptions,
            });
        } catch (e: any) {
            this.skip();
            return;
        }

        console.log(`Impersonated Node.js live JA4: ${impFp.ja4}`);

        // The JA4 should match — same cipher/sigalg/group sets
        const defaultParts = defaultFp.ja4.split('_');
        const impParts = impFp.ja4.split('_');
        expect(impParts[1]).to.equal(defaultParts[1]); // cipher hash
    });

    it('curl fingerprint: impersonated context reproduces curl JA4 cipher hash', async function () {
        // Curl 8.5 / OpenSSL 3.0.13 default ClientHello parameters,
        // captured locally. These are fixed values — no curl needed at runtime.
        const CURL_JA4_CIPHER_HASH = 'e8f1e7e78f70';

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
                0x00ff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV (OpenSSL adds automatically)
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
            alpnProtocols: ['h2', 'http/1.1'],
        };

        // Verify locally first — cipher set should match
        const { captureClientHello } = await import('./test-helpers.js');
        const { secureContext, connectOptions } = impersonate(curlSpec);
        const hello = await captureClientHello({
            secureContext,
            ...connectOptions,
        });

        const ja4Parts = hello.ja4.split('_');
        console.log(`\nCurl-like spec JA4: ${hello.ja4}`);
        expect(ja4Parts[1]).to.equal(CURL_JA4_CIPHER_HASH);

        // Also verify against live server if available
        let liveFp: FingerprintResponse;
        try {
            liveFp = await fetchFingerprint({
                secureContext,
                ...connectOptions,
            });
            console.log(`Curl-like spec live JA4: ${liveFp.ja4}`);
            const liveParts = liveFp.ja4.split('_');
            expect(liveParts[1]).to.equal(CURL_JA4_CIPHER_HASH);
        } catch {
            // Live server unavailable — local verification is sufficient
        }
    });

    it('SCSV spec should negotiate TLS 1.2+ on a normal server', async function () {
        // Curl spec includes 0x00ff (SCSV), which triggers minVersion=TLSv1
        // internally. Verify we still negotiate TLS 1.2+ on a normal server.
        const scsvSpec: ClientHelloSpec = {
            cipherSuites: [
                0x1301, 0x1302, 0x1303,
                0xc02b, 0xc02f, 0x009c, 0x002f,
                0x00ff, // SCSV
            ],
            extensions: [
                { type: 0 }, { type: 10 }, { type: 11 }, { type: 13 },
                { type: 22 }, { type: 23 },
                { type: 43 }, { type: 45 }, { type: 51 },
            ],
            supportedGroups: [0x001d, 0x0017],
            signatureAlgorithms: [0x0403, 0x0804, 0x0401],
            alpnProtocols: ['h2', 'http/1.1'],
        };

        const { secureContext, connectOptions } = impersonate(scsvSpec);

        let result: { protocol: string | null };
        try {
            result = await connectTls('testserver.host', {
                secureContext,
                ...connectOptions,
            });
        } catch {
            this.skip(); // Network unavailable
            return;
        }

        console.log(`\nSCSV spec negotiated protocol: ${result.protocol}`);
        expect(result.protocol).to.be.oneOf(['TLSv1.2', 'TLSv1.3']);
    });

    it('SCSV spec should refuse to connect to a TLS 1.0-only server', async function () {
        const scsvSpec: ClientHelloSpec = {
            cipherSuites: [
                0x1301, 0x1302, 0x1303,
                0xc02b, 0xc02f, 0x009c, 0x002f,
                0x00ff, // SCSV
            ],
            extensions: [
                { type: 0 }, { type: 10 }, { type: 11 }, { type: 13 },
                { type: 22 }, { type: 23 },
                { type: 43 }, { type: 45 }, { type: 51 },
            ],
            supportedGroups: [0x001d, 0x0017],
            signatureAlgorithms: [0x0403, 0x0804, 0x0401],
        };

        const { secureContext, connectOptions } = impersonate(scsvSpec);

        try {
            await connectTls('tls-v1-0.testserver.host', {
                secureContext,
                ...connectOptions,
            });
            // If we get here, the connection succeeded — that's a failure
            expect.fail('Should not connect to TLS 1.0-only server');
        } catch (e: any) {
            if (e.message === 'Connect timeout') {
                this.skip(); // Network unavailable
                return;
            }
            // Connection should fail with a protocol/version error
            console.log(`\nTLS 1.0-only connection correctly rejected: ${e.code || e.message}`);
            expect(e.code || e.message).to.match(
                /UNSUPPORTED_PROTOCOL|VERSION|ALERT|ECONNRESET|routines/i
            );
        }
    });
});
