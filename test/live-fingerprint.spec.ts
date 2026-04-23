import { expect } from 'chai';
import * as tls from 'node:tls';
import * as https from 'node:https';
import { impersonate } from '../src/index.js';
import type { ClientHelloSpec } from '../src/index.js';
import { captureClientHello, expectedFailure } from './test-helpers.js';

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

function fetchUrl<T = unknown>(url: string, options: {
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

// Expected fingerprints — must match the values in the browser-specific spec files
const CHROME_EXPECTED_JA4 = 't13d1516h2_8daaf6152771_d8a2da3f94cd';
const CHROME_EXPECTED_JA3 = 'f418dd9b4f923541607d5763fa771b1f';

const FIREFOX_EXPECTED_JA4 = 't13d1718h2_5b57614c22b0_1ae7ba31360c';
const FIREFOX_EXPECTED_JA3 = 'f656f04be2b252871dab2584ff3392a5';

const SAFARI_EXPECTED_JA4 = 't13d2014h2_a09f3c656075_604f15001eed';
const SAFARI_EXPECTED_JA3 = 'e6313618686ad203ec858e82dbbc1ae0';

describe('Live fingerprint verification', function () {
    this.timeout(15000);

    // --- Browser specs (same as in the browser-specific test files) ---

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

    const safariSpec: ClientHelloSpec = {
        cipherSuites: [
            0x1302, 0x1303, 0x1301,
            0xc02c, 0xc02b, 0xcca9,
            0xc030, 0xc02f, 0xcca8,
            0xc00a, 0xc009, 0xc014, 0xc013,
            0x009d, 0x009c, 0x0035, 0x002f,
            0xc008, 0xc012, 0x000a,
        ],
        extensions: [
            { type: 0 }, { type: 23 }, { type: 65281 },
            { type: 10 }, { type: 11 }, { type: 16 }, { type: 5 },
            { type: 13 }, { type: 18 },
            { type: 51 }, { type: 45 }, { type: 43 },
            { type: 27, data: Buffer.from([0x02, 0x00, 0x02]) },
            { type: 21 },
        ],
        supportedGroups: [0x11ec, 0x001d, 0x0017, 0x0018, 0x0019],
        signatureAlgorithms: [
            0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501, 0x0806, 0x0601, 0x0201,
        ],
        alpnProtocols: ['h2', 'http/1.1'],
    };

    // --- Local fingerprint tests (full JA4 + JA3 verification) ---

    it('Chrome spec should produce the correct JA4 and JA3 locally', expectedFailure('*', async () => {
        const { secureContext, connectOptions } = impersonate(chromeSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.ja4).to.equal(CHROME_EXPECTED_JA4);
        expect(hello.ja3).to.equal(CHROME_EXPECTED_JA3);
    }));

    it('Firefox spec should produce the correct JA4 and JA3 locally', expectedFailure('*', async () => {
        const { secureContext, connectOptions } = impersonate(firefoxSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.ja4).to.equal(FIREFOX_EXPECTED_JA4);
        expect(hello.ja3).to.equal(FIREFOX_EXPECTED_JA3);
    }));

    it('Safari spec should produce the correct JA4 and JA3 locally', expectedFailure('*', async () => {
        const { secureContext, connectOptions } = impersonate(safariSpec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });

        expect(hello.ja4).to.equal(SAFARI_EXPECTED_JA4);
        expect(hello.ja3).to.equal(SAFARI_EXPECTED_JA3);
    }));

    // --- Live server fingerprint tests ---

    it('Chrome spec should produce the correct JA4 and JA3 on a live server', expectedFailure('*', async function () {
        let fp: FingerprintResponse;
        try {
            const { secureContext, connectOptions } = impersonate(chromeSpec);
            fp = await fetchFingerprint({ secureContext, ...connectOptions });
        } catch {
            this.skip(); // Network unavailable
            return;
        }

        expect(fp.ja4).to.equal(CHROME_EXPECTED_JA4);
        expect(fp.ja3).to.equal(CHROME_EXPECTED_JA3);
    }));

    it('Firefox spec should produce the correct JA4 and JA3 on a live server', expectedFailure('*', async function () {
        let fp: FingerprintResponse;
        try {
            const { secureContext, connectOptions } = impersonate(firefoxSpec);
            fp = await fetchFingerprint({ secureContext, ...connectOptions });
        } catch {
            this.skip(); // Network unavailable
            return;
        }

        expect(fp.ja4).to.equal(FIREFOX_EXPECTED_JA4);
        expect(fp.ja3).to.equal(FIREFOX_EXPECTED_JA3);
    }));

    it('Safari spec should produce the correct JA4 and JA3 on a live server', expectedFailure('*', async function () {
        let fp: FingerprintResponse;
        try {
            const { secureContext, connectOptions } = impersonate(safariSpec);
            fp = await fetchFingerprint({ secureContext, ...connectOptions });
        } catch {
            this.skip(); // Network unavailable
            return;
        }

        expect(fp.ja4).to.equal(SAFARI_EXPECTED_JA4);
        expect(fp.ja3).to.equal(SAFARI_EXPECTED_JA3);
    }));

    // --- Round-trip and protocol tests ---

    it('round-trip: Node.js default fingerprint matches via live server', async function () {
        let defaultFp: FingerprintResponse;
        try {
            defaultFp = await fetchFingerprint({
                ALPNProtocols: ['h2', 'http/1.1'],
            });
        } catch {
            this.skip();
            return;
        }

        // Capture Node.js default ClientHello locally to build a spec
        const defaultHello = await captureClientHello({
            ALPNProtocols: ['h2', 'http/1.1'],
        });

        const [, ciphers, extensions, groups, , sigAlgorithms] = defaultHello.fingerprintData;

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
        } catch {
            this.skip();
            return;
        }

        // Full JA4 and JA3 should match
        expect(impFp.ja4).to.equal(defaultFp.ja4);
        expect(impFp.ja3).to.equal(defaultFp.ja3);
    });

    it('SCSV spec should negotiate TLS 1.2+ on a normal server', async function () {
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
            expect.fail('Should not connect to TLS 1.0-only server');
        } catch (e: unknown) {
            const err = e as { message?: string; code?: string };
            if (err.message === 'Connect timeout' || err.code === 'ETIMEDOUT') {
                this.skip(); // Network unavailable
                return;
            }
            expect(err.code || err.message).to.match(
                /UNSUPPORTED_PROTOCOL|VERSION|ALERT|ECONNRESET|routines/i
            );
        }
    });
});
