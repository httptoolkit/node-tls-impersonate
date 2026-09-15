import { expect } from 'chai';
import * as tls from 'node:tls';
import * as os from 'node:os';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { execFileSync } from 'node:child_process';

import { impersonate, impersonateFromClientHello, CannotImpersonateError } from '../src/index.js';
import type { ClientHelloSpec, ImpersonateOptions, UnsupportedFeature } from '../src/index.js';
import { captureRawClientHello, type CapturedClientHello } from './test-helpers.js';

const TLS1_0 = 0x0301;
const TLS1_1 = 0x0302;
const TLS1_2 = 0x0303;
const TLS1_3 = 0x0304;

const EXT_SIGNATURE_ALGORITHMS = 13;
const EXT_SUPPORTED_VERSIONS = 43;
const EXT_PSK_KEY_EXCHANGE_MODES = 45;
const EXT_KEY_SHARE = 51;

const LEGACY_CLIENT_OPTIONS = { ciphers: 'DEFAULT:@SECLEVEL=0', minVersion: 'TLSv1' } as const;

/** Every refusal reports the same reason - what differs is the hello that caused it. */
const CANNOT_MIRROR = 'no available TLS version range can functionally mirror';

/**
 * A ClientHello shaped like Mbed TLS 2.28 - the TLS stack behind Unity's networking,
 * and typical of embedded TLS 1.2-only clients generally. Its signature algorithms
 * pair {SHA512, SHA384, SHA256, SHA224} with ECDSA and RSA-PKCS1 and include no PSS,
 * which is unusable for TLS 1.3 CertificateVerify against an RSA certificate.
 */
const TLS12_ONLY_SPEC: ClientHelloSpec = {
    cipherSuites: [
        0xc02c, 0xc030, 0xc02b, 0xc02f, 0xc024, 0xc028, 0xc023, 0xc027,
        0xc00a, 0xc014, 0xc009, 0xc013, 0x009d, 0x009c, 0x003d, 0x003c, 0x0035, 0x002f,
    ],
    extensions: [
        { type: 0 }, { type: 65281 }, { type: 13 }, { type: 10 },
        { type: 11 }, { type: 22 }, { type: 23 }, { type: 35 },
    ],
    supportedGroups: [0x0017, 0x0018, 0x0019, 0x001d],
    signatureAlgorithms: [0x0603, 0x0601, 0x0503, 0x0501, 0x0403, 0x0401, 0x0303, 0x0301],
    ecPointFormats: [0],
    legacyVersion: TLS1_2,
};

/** The same client, but TLS 1.3-capable: supported_versions plus its companion extensions. */
const TLS13_SPEC: ClientHelloSpec = {
    ...TLS12_ONLY_SPEC,
    cipherSuites: [0x1301, 0x1302, 0x1303, ...TLS12_ONLY_SPEC.cipherSuites],
    extensions: [
        ...TLS12_ONLY_SPEC.extensions,
        { type: 43 }, { type: 45 }, { type: 51 },
    ],
    signatureAlgorithms: [0x0403, 0x0804, 0x0401, 0x0503, 0x0805, 0x0501],
    supportedVersions: [TLS1_3, TLS1_2],
};

/** A client whose offer only works at TLS 1.3: no TLS 1.2 cipher suites at all. */
function tls13CiphersOnly(supportedVersions?: number[]): ClientHelloSpec {
    return {
        ...TLS13_SPEC,
        cipherSuites: [0x1301, 0x1302, 0x1303],
        supportedVersions,
        ...(supportedVersions ? {} : {
            extensions: TLS13_SPEC.extensions.filter((e) => e.type !== 43),
        }),
    };
}

function specWithVersions(
    supportedVersions: number[] | undefined,
    extra: Partial<ClientHelloSpec> = {}
): ClientHelloSpec {
    return {
        ...TLS13_SPEC,
        ...(supportedVersions ? { supportedVersions } : { supportedVersions: undefined }),
        ...extra,
    };
}

function emittedVersions(hello: CapturedClientHello): number[] | undefined {
    const ext = hello.raw.extensions.find((e) => e.id === EXT_SUPPORTED_VERSIONS);
    if (!ext) return undefined;
    return (ext.data!.versions as number[]).filter((v) => (v & 0x0f0f) !== 0x0a0a);
}

function captureSpec(spec: ClientHelloSpec, options?: ImpersonateOptions) {
    const { tlsOptions, unsupported } = impersonate(spec, options);
    return captureRawClientHello(tlsOptions).then((hello) => ({ hello, unsupported }));
}

/** Run impersonate() expecting it to refuse, and return the error it threw. */
function expectCannotImpersonate(
    spec: ClientHelloSpec,
    options?: ImpersonateOptions
): CannotImpersonateError {
    try {
        impersonate(spec, options);
    } catch (e) {
        if (e instanceof CannotImpersonateError) return e;
        throw e;
    }
    throw new Error('Expected impersonate() to refuse this spec, but it succeeded');
}

function gapsFor(unsupported: UnsupportedFeature[], kind: UnsupportedFeature['kind']) {
    return unsupported.filter((u) => u.kind === kind);
}

// Generate a self-signed cert with the given openssl key args, returned as PEMs.
function generateCert(keyArgs: string[]): { key: string; cert: string } {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tls-versions-'));
    try {
        execFileSync('openssl', [
            'req', '-x509', '-nodes', '-days', '1', '-subj', '/CN=localhost',
            '-keyout', path.join(dir, 'k.pem'), '-out', path.join(dir, 'c.pem'),
            ...keyArgs,
        ], { stdio: 'pipe' });
        return {
            key: fs.readFileSync(path.join(dir, 'k.pem'), 'utf-8'),
            cert: fs.readFileSync(path.join(dir, 'c.pem'), 'utf-8'),
        };
    } finally {
        fs.rmSync(dir, { recursive: true, force: true });
    }
}

interface HandshakeResult {
    ok: boolean;
    protocol?: string | null;
    clientError?: string;
    serverError?: string;
}

/** Handshake against a local server with the given cert, using the given connect options. */
function handshake(
    serverOptions: tls.TlsOptions,
    clientOptions: tls.ConnectionOptions
): Promise<HandshakeResult> {
    return new Promise((resolve) => {
        let serverError: string | undefined;
        const server = tls.createServer(serverOptions, (socket) => socket.end('hi'));
        server.on('tlsClientError', (e) => { serverError = e.message.trim(); });

        server.listen(0, '127.0.0.1', () => {
            const { port } = server.address() as { port: number };
            const done = (result: HandshakeResult) => {
                server.close();
                // Let the server's error event land before reporting.
                setTimeout(() => resolve({ ...result, serverError }), 20);
            };

            const socket = tls.connect({
                host: '127.0.0.1', port, servername: 'localhost',
                rejectUnauthorized: false, ...clientOptions,
            }, () => {
                const protocol = socket.getProtocol();
                socket.destroy();
                done({ ok: true, protocol });
            });
            socket.on('error', (e) => done({ ok: false, clientError: e.message.trim() }));
        });
    });
}

let rsaCert: { key: string; cert: string };
let ecdsaCert: { key: string; cert: string };

describe('TLS version mirroring', () => {

    before(function () {
        this.timeout(20000);
        rsaCert = generateCert(['-newkey', 'rsa:2048']);
        ecdsaCert = generateCert(['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256']);
    });

    describe('takes its version ceiling from the hello', () => {

        it('caps at TLS 1.2 for a hello with no supported_versions', async () => {
            const { hello } = await captureSpec(TLS12_ONLY_SPEC);

            expect(emittedVersions(hello)).to.equal(undefined);
            expect(hello.extensions).to.not.include(EXT_SUPPORTED_VERSIONS);
            expect(hello.extensions).to.not.include(EXT_KEY_SHARE);
            expect(hello.extensions).to.not.include(EXT_PSK_KEY_EXCHANGE_MODES);
            expect(hello.ja4.slice(0, 3)).to.equal('t12');
        });

        it('offers TLS 1.3 when supported_versions asks for it', async () => {
            const { hello } = await captureSpec(TLS13_SPEC);

            expect(emittedVersions(hello)).to.deep.equal([TLS1_3, TLS1_2]);
            expect(hello.extensions).to.include(EXT_KEY_SHARE);
            expect(hello.ja4.slice(0, 3)).to.equal('t13');
        });

        it('caps at TLS 1.2 when supported_versions lists only TLS 1.2', async () => {
            const { hello, unsupported } = await captureSpec(specWithVersions([TLS1_2]));

            expect(hello.ja4.slice(0, 3)).to.equal('t12');
            expect(emittedVersions(hello)).to.equal(undefined);
            // We can't reproduce the extension itself: OpenSSL only emits it for TLS 1.3.
            expect(unsupported.map((u) => u.id)).to.include(EXT_SUPPORTED_VERSIONS);
        });

        it('offers only TLS 1.3 when supported_versions lists only TLS 1.3', async () => {
            const { hello } = await captureSpec(specWithVersions([TLS1_3]));

            expect(emittedVersions(hello)).to.deep.equal([TLS1_3]);
            expect(hello.ja4.slice(0, 3)).to.equal('t13');
        });

        it('ignores GREASE values in supported_versions', async () => {
            const { hello } = await captureSpec(specWithVersions([0x0a0a, TLS1_3, TLS1_2]));

            expect(emittedVersions(hello)).to.deep.equal([TLS1_3, TLS1_2]);
        });

        it('uses legacy_version as the ceiling when there is no supported_versions', async () => {
            const { hello } = await captureSpec(
                { ...TLS12_ONLY_SPEC, legacyVersion: TLS1_0 },
                { security: 'insecure' }
            );

            expect(hello.ja4.slice(0, 3)).to.equal('t10');
        });

        it('never offers more than TLS 1.3, whatever the hello claims', async () => {
            const { hello } = await captureSpec(specWithVersions([0x0305, TLS1_3]));

            expect(emittedVersions(hello)).to.deep.equal([TLS1_3]);
        });
    });

    describe('reads the version band from every source the spec offers', () => {

        // A hand-written spec: TLS 1.3 cipher suites, but no supported_versions extension
        // listed and no legacy_version. Only parsed hellos carry legacy_version, so a spec
        // like this must not be read as a pre-TLS1.3 client.
        const handWritten: ClientHelloSpec = {
            cipherSuites: [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f],
            extensions: [{ type: 0 }, { type: 23 }, { type: 16 }],
            supportedGroups: [0x001d, 0x0017, 0x0018],
            signatureAlgorithms: [0x0403, 0x0804, 0x0401],
        };

        it('assumes a modern client when the spec states no version at all', async () => {
            const { hello, unsupported } = await captureSpec(handWritten);

            expect(hello.ja4.slice(0, 3)).to.equal('t13');
            expect(hello.ciphers).to.deep.equal(handWritten.cipherSuites);
            expect(unsupported).to.deep.equal([]);
        });

        it('honours supportedVersions even when extension 43 is not in the list', async () => {
            const { hello } = await captureSpec({
                ...handWritten,
                supportedVersions: [TLS1_3, TLS1_2],
            });

            expect(emittedVersions(hello)).to.deep.equal([TLS1_3, TLS1_2]);
        });
    });

    describe('limits its version floor according to the security mode, not just the hello', () => {

        it('does not widen past what the hello listed, even in insecure mode', async () => {
            // The mode's floor is a limit, not a target: a client that offers TLS 1.3 down
            // to 1.2 must not be widened to 1.0 just because the mode would allow it.
            const secure = await captureSpec(TLS13_SPEC);
            const insecure = await captureSpec(TLS13_SPEC, { security: 'insecure' });

            expect(emittedVersions(secure.hello)).to.deep.equal([TLS1_3, TLS1_2]);
            expect(emittedVersions(insecure.hello)).to.deep.equal([TLS1_3, TLS1_2]);
        });

        it('blocks TLS 1.2 below a TLS 1.3-only band even when emitting SCSV', async () => {
            // SCSV emission needs minVersion lowered to TLSv1, so every version below the
            // resolved floor has to be blocked again by option flags - TLS 1.2 included.
            const { hello } = await captureSpec({
                ...TLS13_SPEC,
                cipherSuites: [...TLS13_SPEC.cipherSuites, 0x00ff],
                supportedVersions: [TLS1_3],
            }, { security: 'insecure' });

            expect(emittedVersions(hello)).to.deep.equal([TLS1_3]);
        });


        const legacyCapableSpec = specWithVersions([TLS1_3, TLS1_2, TLS1_1, TLS1_0]);

        it('never negotiates below TLS 1.2 in secure mode, even when the hello does', async () => {
            const { hello, unsupported } = await captureSpec(legacyCapableSpec);

            expect(emittedVersions(hello)).to.deep.equal([TLS1_3, TLS1_2]);
            expect(gapsFor(unsupported, 'version')).to.have.lengthOf(1);
        });

        it('offers the legacy versions the hello asked for in insecure mode', async () => {
            const { hello, unsupported } = await captureSpec(
                legacyCapableSpec, { security: 'insecure' }
            );

            expect(emittedVersions(hello)).to.deep.equal([TLS1_3, TLS1_2, TLS1_1, TLS1_0]);
            expect(gapsFor(unsupported, 'version')).to.have.lengthOf(0);
        });

        it('reproduces a TLS 1.0-only hello in insecure mode', async () => {
            const { hello, unsupported } = await captureSpec(
                { ...TLS12_ONLY_SPEC, legacyVersion: TLS1_0 }, { security: 'insecure' }
            );

            expect(hello.ja4.slice(0, 3)).to.equal('t10');
            expect(gapsFor(unsupported, 'version')).to.have.lengthOf(0);
        });
    });

    describe('completes handshakes that the mirrored client could complete', () => {

        it('reaches an RSA-certificate server from a TLS 1.2-only hello', async () => {
            const { tlsOptions } = impersonate(TLS12_ONLY_SPEC);
            const result = await handshake(rsaCert, tlsOptions);

            expect(result.clientError, 'client error').to.equal(undefined);
            expect(result.ok).to.equal(true);
            expect(result.protocol).to.equal('TLSv1.2');
        });

        it('reaches an ECDSA-certificate server from a TLS 1.2-only hello', async () => {
            const { tlsOptions } = impersonate(TLS12_ONLY_SPEC);
            const result = await handshake(ecdsaCert, tlsOptions);

            expect(result.clientError, 'client error').to.equal(undefined);
            expect(result.protocol).to.equal('TLSv1.2');
        });

        it('still negotiates TLS 1.3 for a TLS 1.3-capable hello', async () => {
            const { tlsOptions } = impersonate(TLS13_SPEC);
            const result = await handshake(rsaCert, tlsOptions);

            expect(result.clientError, 'client error').to.equal(undefined);
            expect(result.protocol).to.equal('TLSv1.3');
        });

        it('reaches a TLS 1.0-only server in insecure mode', async () => {
            const { tlsOptions } = impersonate(
                { ...TLS12_ONLY_SPEC, legacyVersion: TLS1_0 }, { security: 'insecure' }
            );
            const result = await handshake({
                ...rsaCert, minVersion: 'TLSv1', maxVersion: 'TLSv1',
                ciphers: 'DEFAULT:@SECLEVEL=0',
            }, tlsOptions);

            expect(result.clientError, 'client error').to.equal(undefined);
            expect(result.protocol).to.equal('TLSv1');
        });

        it('refuses a TLS 1.0-only server from a mirrored TLS 1.2 hello', async () => {
            const { tlsOptions } = impersonate(TLS12_ONLY_SPEC);
            const result = await handshake({
                ...rsaCert, minVersion: 'TLSv1', maxVersion: 'TLSv1',
                ciphers: 'DEFAULT:@SECLEVEL=0',
            }, tlsOptions);

            expect(result.ok).to.equal(false);
        });
    });

    describe('never leaks OpenSSL defaults into the mirrored hello', () => {

        it("doesn't advertise default TLS 1.3 suites when the hello offers none", async () => {
            // A TLS 1.3 hello with only TLS 1.2 cipher suites. Left to itself OpenSSL fills
            // in its own three default TLS 1.3 suites, which the client never offered - so
            // we drop to TLS 1.2 instead, which is all such a client could have negotiated.
            const { hello, unsupported } = await captureSpec(specWithVersions([TLS1_3, TLS1_2], {
                cipherSuites: TLS12_ONLY_SPEC.cipherSuites,
            }));

            expect(hello.ciphers.filter((c) => c >= 0x1300 && c <= 0x13ff)).to.deep.equal([]);
            expect(emittedVersions(hello)).to.equal(undefined);
            expect(gapsFor(unsupported, 'version').map((u) => u.id)).to.deep.equal([TLS1_2]);
            expect(unsupported.map((u) => u.id)).to.include(EXT_SUPPORTED_VERSIONS);
        });

        it('drops TLS 1.3 suites when TLS 1.3 is not negotiable, and reports them', async () => {
            const { hello, unsupported } = await captureSpec({
                ...TLS12_ONLY_SPEC,
                cipherSuites: [0x1301, 0x1302, ...TLS12_ONLY_SPEC.cipherSuites],
            });

            expect(hello.ciphers.filter((c) => c >= 0x1300 && c <= 0x13ff)).to.deep.equal([]);
            const cipherGaps = gapsFor(unsupported, 'cipherSuite').map((u) => u.id);
            expect(cipherGaps).to.include(0x1301);
            expect(cipherGaps).to.include(0x1302);
        });

        it('reports each gap once, without collapsing different kinds', async () => {
            // TLS 1.3 suites dropped below TLS 1.3 are reported specifically, and must not
            // also surface from the general availability check. 0x002b is both an unknown
            // cipher suite and the supported_versions extension type: different namespaces,
            // so both gaps have to survive.
            const { unsupported } = impersonate({
                ...TLS12_ONLY_SPEC,
                cipherSuites: [0x1301, 0x1302, 0x002b, ...TLS12_ONLY_SPEC.cipherSuites],
                extensions: [...TLS12_ONLY_SPEC.extensions, { type: EXT_SUPPORTED_VERSIONS }],
                supportedVersions: [TLS1_2],
            });

            const keys = unsupported.map((u) => `${u.kind}:${u.id}`);
            expect(keys).to.deep.equal([...new Set(keys)]);
            expect(keys).to.include('cipherSuite:43');
            expect(keys).to.include('extension:43');
        });

        it('reports a gap when no requested signature algorithm could be reproduced', async () => {
            // The extension is listed, but nothing in it maps - so OpenSSL advertises its
            // own defaults. That's the same default-leak as the cipher cases, and must
            // not pass silently just because the list happens to be empty.
            const { hello, unsupported } = await captureSpec({
                ...TLS13_SPEC,
                signatureAlgorithms: [0x0999, 0x0998], // Not real signature algorithms
            });

            expect(hello.signatureAlgorithms.length).to.be.greaterThan(2);
            expect(unsupported.map((u) => u.id)).to.include(EXT_SIGNATURE_ALGORITHMS);
        });

        it('mirrors at TLS 1.3 when only the TLS 1.2 suites are missing from OpenSSL', async () => {
            // Usable TLS 1.3 suites alongside TLS 1.2 suites OpenSSL 3.5 dropped (3DES).
            // The TLS 1.2 half is unreproducible, but the client is fine at TLS 1.3.
            const { hello, unsupported } = await captureSpec({
                ...TLS13_SPEC,
                cipherSuites: [0x1301, 0x1302, 0x000a, 0x0016],
            });

            expect(hello.ciphers).to.deep.equal([0x1301, 0x1302]);
            expect(emittedVersions(hello)).to.deep.equal([TLS1_3]);
            const cipherGaps = gapsFor(unsupported, 'cipherSuite').map((u) => u.id);
            expect(cipherGaps).to.deep.equal([0x000a, 0x0016]);
        });

        it('builds a context for a hello with no signature_algorithms at all', async () => {
            // TLS 1.0/1.1 clients predate the extension and send no sigalgs whatsoever.
            const spec: ClientHelloSpec = {
                ...TLS12_ONLY_SPEC,
                extensions: TLS12_ONLY_SPEC.extensions.filter((e) => e.type !== 13),
                signatureAlgorithms: [],
                legacyVersion: TLS1_0,
            };

            const { hello } = await captureSpec(spec, { security: 'insecure' });

            expect(hello.extensions).to.not.include(EXT_SIGNATURE_ALGORITHMS);
            expect(hello.ja4.slice(0, 3)).to.equal('t10');
        });

        it('reports signature_algorithms when TLS 1.2+ forces OpenSSL to emit it', async () => {
            const spec: ClientHelloSpec = {
                ...TLS12_ONLY_SPEC,
                extensions: TLS12_ONLY_SPEC.extensions.filter((e) => e.type !== 13),
                signatureAlgorithms: [],
            };

            const { hello, unsupported } = await captureSpec(spec);

            expect(hello.extensions).to.include(EXT_SIGNATURE_ALGORITHMS);
            expect(unsupported.map((u) => u.id)).to.include(EXT_SIGNATURE_ALGORITHMS);
        });
    });

    describe('takes its version floor from the cipher suites too', () => {

        it("doesn't advertise default TLS 1.2 suites when the hello offers none", async () => {
            // The mirror image of the TLS 1.3 case: an empty TLS 1.2 cipher list makes
            // OpenSSL substitute its own default, dozens of suites the client never sent.
            const { hello, unsupported } = await captureSpec(
                tls13CiphersOnly([TLS1_3, TLS1_2])
            );

            expect(hello.ciphers).to.deep.equal([0x1301, 0x1302, 0x1303]);
            expect(emittedVersions(hello)).to.deep.equal([TLS1_3]);
            expect(gapsFor(unsupported, 'version').map((u) => u.id)).to.deep.equal([TLS1_3]);
        });

        it('reports no gap when the hello only asked for TLS 1.3 anyway', async () => {
            const { hello, unsupported } = await captureSpec(tls13CiphersOnly([TLS1_3]));

            expect(hello.ciphers).to.deep.equal([0x1301, 0x1302, 0x1303]);
            expect(emittedVersions(hello)).to.deep.equal([TLS1_3]);
            expect(gapsFor(unsupported, 'version')).to.have.lengthOf(0);
        });

        it('still negotiates TLS 1.3 against a real server', async () => {
            const { tlsOptions } = impersonate(tls13CiphersOnly([TLS1_3, TLS1_2]));
            const result = await handshake(rsaCert, tlsOptions);

            expect(result.clientError, 'client error').to.equal(undefined);
            expect(result.protocol).to.equal('TLSv1.3');
        });
    });

    describe('refuses hellos it cannot mirror at all', () => {

        // Every one of these leaves no version both the hello and the mode can negotiate,
        // so there's nothing to mirror. Approximating any of them would mean offering
        // parameters the client never sent.
        const unmirrorable: Array<[string, ClientHelloSpec, ImpersonateOptions?]> = [
            ['a TLS 1.0-only hello in secure mode',
                { ...TLS12_ONLY_SPEC, legacyVersion: TLS1_0 }],
            ['a TLS 1.1-only hello in secure mode',
                { ...TLS12_ONLY_SPEC, legacyVersion: TLS1_1 }],
            ['an SSLv3 hello even in insecure mode',
                { ...TLS12_ONLY_SPEC, legacyVersion: 0x0300 }, { security: 'insecure' }],
            ['a hello listing only versions we cannot offer',
                { ...TLS13_SPEC, supportedVersions: [0x0a0a, 0x0300] }], // GREASE + SSLv3
            ['a hello with no version its cipher suites can negotiate',
                tls13CiphersOnly()], // TLS 1.3 suites, but it claims TLS 1.2 at best
            ['a hello with no reproducible cipher suites at all',
                { ...TLS12_ONLY_SPEC, cipherSuites: [0x0099, 0x0098] }],
        ];

        for (const [label, spec, options] of unmirrorable) {
            it(`refuses ${label}`, () => {
                const error = expectCannotImpersonate(spec, options);

                expect(error.code).to.equal('ERR_CANNOT_IMPERSONATE');
                expect(error.message).to.contain(CANNOT_MIRROR);
            });
        }

        it('still reports which cipher suites were the problem', () => {
            // An RC4/3DES-era client: OpenSSL 3.5 has none of these, so there is no offer
            // left to reproduce. This used to escape as a raw ERR_SSL_NO_CIPHER_MATCH.
            const error = expectCannotImpersonate({
                ...TLS12_ONLY_SPEC,
                cipherSuites: [0x000a, 0x0016],
                legacyVersion: TLS1_2,
            }, { security: 'insecure' });

            expect(gapsFor(error.unsupported, 'cipherSuite').map((u) => u.id))
                .to.deep.equal([0x000a, 0x0016]);
        });
    });

    describe('round-trips a real captured hello at every version', () => {

        const clients: Array<[string, tls.ConnectionOptions]> = [
            ['TLS 1.0', { ...LEGACY_CLIENT_OPTIONS, maxVersion: 'TLSv1' }],
            ['TLS 1.1', { ...LEGACY_CLIENT_OPTIONS, maxVersion: 'TLSv1.1' }],
            ['TLS 1.2', { ...LEGACY_CLIENT_OPTIONS, maxVersion: 'TLSv1.2' }],
            ['TLS 1.3', { ...LEGACY_CLIENT_OPTIONS, maxVersion: 'TLSv1.3' }],
        ];

        for (const [label, clientOptions] of clients) {
            it(`reproduces a ${label} client's JA3 and JA4 exactly`, async () => {
                const original = await captureRawClientHello(clientOptions);

                const { tlsOptions } = impersonateFromClientHello(original.raw, {
                    security: 'insecure', // Legacy versions are only negotiable here
                });
                const mirrored = await captureRawClientHello(tlsOptions);

                expect(mirrored.ja4).to.equal(original.ja4);
                expect(mirrored.ja3).to.equal(original.ja3);
            });
        }
    });
});
