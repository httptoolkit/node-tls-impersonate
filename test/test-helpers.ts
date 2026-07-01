import * as tls from 'node:tls';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execSync } from 'node:child_process';
import { satisfies } from 'semver';
import { trackClientHellos, getExtensionData } from 'read-tls-client-hello';
import { impersonate, type ClientHelloSpec } from '../src/index.js';

/** Fingerprint-oriented view of a captured ClientHello, derived from
 *  read-tls-client-hello v2's raw message. The array fields are GREASE-filtered
 *  to match JA3/JA4 fingerprint semantics; use `raw` for the unfiltered message
 *  (including GREASE and per-extension data). */
export interface CapturedClientHello {
    version: number;
    ciphers: number[];
    extensions: number[];
    groups: number[];
    ecPointFormats: number[];
    signatureAlgorithms: number[];
    ja3: string;
    ja4: string;
    serverName: string | undefined;
    alpnProtocols: string[] | undefined;
    raw: NonNullable<tls.TLSSocket['tlsClientHello']>;
}

interface SelfSignedCert {
    key: string;
    cert: string;
}

// IANA extension name lookup for readable output
const EXTENSION_NAMES: Record<number, string> = {
    0: 'server_name',
    1: 'max_fragment_length',
    5: 'status_request',
    10: 'supported_groups',
    11: 'ec_point_formats',
    13: 'signature_algorithms',
    16: 'application_layer_protocol_negotiation',
    18: 'signed_certificate_timestamp',
    21: 'padding',
    22: 'encrypt_then_mac',
    23: 'extended_master_secret',
    27: 'compress_certificate',
    28: 'record_size_limit',
    34: 'delegated_credentials',
    35: 'session_ticket',
    41: 'pre_shared_key',
    42: 'early_data',
    43: 'supported_versions',
    44: 'cookie',
    45: 'psk_key_exchange_modes',
    49: 'post_handshake_auth',
    50: 'signature_algorithms_cert',
    51: 'key_share',
    17513: 'extensionRenegotiationInfo',
    17613: 'application_settings',
    65037: 'encrypted_client_hello',
    65281: 'renegotiation_info',
};

/** Check if a value is a GREASE extension type (0x?a?a pattern) */
export function isGreaseValue(id: number): boolean {
    return (id & 0x0f0f) === 0x0a0a;
}

export function extensionName(id: number): string {
    if (isGreaseValue(id)) return `GREASE(0x${id.toString(16)})`;
    return EXTENSION_NAMES[id] || `unknown(${id})`;
}

let cachedCert: SelfSignedCert | undefined;

/**
 * Generate a self-signed certificate for testing (cached for performance)
 */
function generateSelfSignedCert(): SelfSignedCert {
    if (cachedCert) return cachedCert;

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'tls-test-'));
    const keyFile = path.join(tmpDir, 'key.pem');
    const certFile = path.join(tmpDir, 'cert.pem');

    try {
        execSync(
            `openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 ` +
            `-keyout "${keyFile}" -out "${certFile}" -days 1 -nodes ` +
            `-subj "/CN=localhost"`,
            { stdio: 'pipe' }
        );

        cachedCert = {
            key: fs.readFileSync(keyFile, 'utf-8'),
            cert: fs.readFileSync(certFile, 'utf-8'),
        };
        return cachedCert;
    } finally {
        fs.rmSync(tmpDir, { recursive: true, force: true });
    }
}

function toCapturedHello(
    hello: NonNullable<tls.TLSSocket['tlsClientHello']>
): CapturedClientHello {
    const noGrease = (ids: number[]) => ids.filter((id) => !isGreaseValue(id));
    return {
        version: hello.version,
        ciphers: noGrease(hello.cipherSuites),
        extensions: noGrease(hello.extensions.map((e) => e.id)),
        groups: noGrease(getExtensionData(hello, 10)?.groups ?? []),
        ecPointFormats: getExtensionData(hello, 11)?.formats ?? [],
        signatureAlgorithms: noGrease(getExtensionData(hello, 13)?.algorithms ?? []),
        ja3: hello.ja3,
        ja4: hello.ja4,
        serverName: getExtensionData(hello, 0)?.serverName,
        alpnProtocols: getExtensionData(hello, 16)?.protocols,
        raw: hello,
    };
}

/**
 * Capture the TLS ClientHello fingerprint from a connection using a given SecureContext.
 *
 * Creates a temporary TLS server, connects with the provided context,
 * and returns the parsed ClientHello data including JA3/JA4 fingerprints.
 */
export async function captureClientHello(options?: {
    secureContext?: tls.SecureContext;
    ALPNProtocols?: string[];
    requestOCSP?: boolean;
    servername?: string;
}): Promise<CapturedClientHello> {
    const { key, cert } = generateSelfSignedCert();

    const server = tls.createServer({
        key,
        cert,
    });

    trackClientHellos(server);

    return new Promise<CapturedClientHello>((resolve, reject) => {
        const timeout = setTimeout(() => {
            cleanup();
            reject(new Error('Timeout waiting for TLS handshake'));
        }, 5000);

        function cleanup() {
            clearTimeout(timeout);
            server.close();
        }

        server.on('secureConnection', (socket) => {
            const hello = socket.tlsClientHello;
            socket.destroy();
            cleanup();

            if (!hello) {
                reject(new Error('No ClientHello data captured'));
                return;
            }

            resolve(toCapturedHello(hello));
        });

        server.on('tlsClientError', (err) => {
            // Ignore client errors - the handshake may still have captured the ClientHello
        });

        server.listen(0, '127.0.0.1', () => {
            const addr = server.address() as { port: number };

            const connectOpts: tls.ConnectionOptions = {
                host: '127.0.0.1',
                port: addr.port,
                servername: options?.servername ?? 'localhost',
                rejectUnauthorized: false,
                ...(options?.ALPNProtocols ? { ALPNProtocols: options.ALPNProtocols } : {}),
                ...(options?.secureContext ? { secureContext: options.secureContext } : {}),
                ...(options?.requestOCSP ? { requestOCSP: true } : {}),
            };

            // Don't destroy client on connect - let the server's secureConnection
            // event fire first. The server handler will destroy both sides.
            const client = tls.connect(connectOpts);

            client.on('error', () => {
                // Ignore client-side errors (self-signed cert etc)
            });
        });
    });
}

/**
 * - Google: BoringSSL, ALPS-supporting, very strict
 * - Cloudflare: ECH-supporting, sends retry_configs on GREASE ECH
 * - GitHub: Common production target (AWS/ALB)
 */
const REAL_WORLD_TARGETS = [
    'www.google.com',
    'www.cloudflare.com',
    'github.com',
];

export function runRealWorldTests(name: string, spec: ClientHelloSpec): void {
    for (const host of REAL_WORLD_TARGETS) {
        it(`${name} spec should complete TLS handshake with ${host}`, async function () {
            const { secureContext, connectOptions } = impersonate(spec);
            const result = await verifyRemoteHandshake.call(this, host, {
                secureContext,
                ...connectOptions,
            });
            if (!result.protocol) {
                throw new Error(`No protocol negotiated with ${host}`);
            }
        });
    }
}

export async function verifyRemoteHandshake(
    this: Mocha.Context | void,
    hostname: string,
    options: {
        secureContext?: tls.SecureContext;
        ALPNProtocols?: string[];
        requestOCSP?: boolean;
    }
): Promise<{ protocol: string | null; alpn: string | false | null }> {
    const result = await new Promise<
        | { ok: true; protocol: string | null; alpn: string | false | null }
        | { ok: false; error: string }
    >((resolve) => {
        const timer = setTimeout(() => resolve({ ok: false, error: 'timeout' }), 8000);
        const socket = tls.connect({
            host: hostname,
            port: 443,
            servername: hostname,
            ...options,
        });
        socket.on('secureConnect', () => {
            clearTimeout(timer);
            const protocol = socket.getProtocol();
            const alpn = socket.alpnProtocol;
            socket.destroy();
            resolve({ ok: true, protocol, alpn });
        });
        socket.on('error', (e: unknown) => {
            clearTimeout(timer);
            const err = e as { code?: string; message?: string };
            socket.destroy();
            resolve({ ok: false, error: err.code || err.message || 'unknown' });
        });
    });

    if (result.ok) return result;

    // Network-level errors → skip (not our problem)
    const networkErrors = ['ENOTFOUND', 'ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH', 'timeout'];
    if (networkErrors.includes(result.error) && this && 'skip' in this) {
        this.skip();
    }
    throw new Error(`Handshake to ${hostname} failed: ${result.error}`);
}

export function expectedFailure(
    nodeVersions: string,
    fn: (this: Mocha.Context) => Promise<void>
): (this: Mocha.Context) => Promise<void> {
    const shouldExpectFailure = satisfies(process.version, nodeVersions, { includePrerelease: true });

    return async function (this: Mocha.Context) {
        try {
            await fn.call(this);
        } catch (e) {
            if (shouldExpectFailure && e instanceof Error && e.name === 'AssertionError') {
                this.skip(); // Failed as expected on this version
                return;
            }
            throw e;
        }
        if (shouldExpectFailure) {
            throw new Error(
                `Expected this test to fail on Node ${process.version} (range: ${nodeVersions}), ` +
                'but it passed — the underlying issue may be fixed. ' +
                'Update the test to narrow the expectedFailure range or remove it.'
            );
        }
    };
}

/**
 * Format captured ClientHello data for readable logging
 */
export function formatClientHello(hello: CapturedClientHello): string {
    const hex = (n: number) => '0x' + n.toString(16).padStart(4, '0');

    const lines = [
        `JA4: ${hello.ja4}`,
        `JA3: ${hello.ja3}`,
        `SNI: ${hello.serverName ?? '(none)'}`,
        `ALPN: ${hello.alpnProtocols?.join(', ') ?? '(none)'}`,
        `TLS Version: ${hex(hello.version)}`,
        `Ciphers (${hello.ciphers.length}): ${hello.ciphers.map(hex).join(', ')}`,
        `Extensions (${hello.extensions.length}): ${hello.extensions.map(e => `${e}(${extensionName(e)})`).join(', ')}`,
        `Groups (${hello.groups.length}): ${hello.groups.map(hex).join(', ')}`,
        `Curve Formats: ${hello.ecPointFormats.map(f => '0x' + f.toString(16)).join(', ')}`,
        `Sig Algorithms (${hello.signatureAlgorithms.length}): ${hello.signatureAlgorithms.map(hex).join(', ')}`,
    ];

    return lines.join('\n');
}
