import * as tls from 'node:tls';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { execSync } from 'node:child_process';
import { satisfies } from 'semver';
import { trackClientHellos, type TlsHelloData } from 'read-tls-client-hello';

export interface CapturedClientHello extends TlsHelloData {
    ja3: string;
    ja4: string;
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

            resolve(hello as CapturedClientHello);
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
    const [version, ciphers, extensions, groups, curveFormats, sigAlgorithms] = hello.fingerprintData;

    const lines = [
        `JA4: ${hello.ja4}`,
        `JA3: ${hello.ja3}`,
        `SNI: ${hello.serverName ?? '(none)'}`,
        `ALPN: ${hello.alpnProtocols?.join(', ') ?? '(none)'}`,
        `TLS Version: 0x${version.toString(16).padStart(4, '0')}`,
        `Ciphers (${ciphers.length}): ${ciphers.map(c => '0x' + c.toString(16).padStart(4, '0')).join(', ')}`,
        `Extensions (${extensions.length}): ${extensions.map(e => `${e}(${extensionName(e)})`).join(', ')}`,
        `Groups (${groups.length}): ${groups.map(g => '0x' + g.toString(16).padStart(4, '0')).join(', ')}`,
        `Curve Formats: ${curveFormats.map(f => '0x' + f.toString(16)).join(', ')}`,
        `Sig Algorithms (${sigAlgorithms.length}): ${sigAlgorithms.map(s => '0x' + s.toString(16).padStart(4, '0')).join(', ')}`,
    ];

    return lines.join('\n');
}
