import tls from 'node:tls';
import crypto from 'node:crypto';
import {
    addCustomExtension,
    isPredefinedExtension,
    enableCompressCertificate,
    enablePostHandshakeAuth,
    setOptions,
    constants,
} from './native.js';

// ─── Lookup Tables ───────────────────────────────────────────────────────────

/** Cipher suite IANA ID → OpenSSL name */
const CIPHER_NAMES: Record<number, string> = {
    // TLS 1.3
    0x1301: 'TLS_AES_128_GCM_SHA256',
    0x1302: 'TLS_AES_256_GCM_SHA384',
    0x1303: 'TLS_CHACHA20_POLY1305_SHA256',
    0x1304: 'TLS_AES_128_CCM_SHA256',
    0x1305: 'TLS_AES_128_CCM_8_SHA256',

    // TLS 1.2 ECDHE+ECDSA
    0xc02b: 'ECDHE-ECDSA-AES128-GCM-SHA256',
    0xc02c: 'ECDHE-ECDSA-AES256-GCM-SHA384',
    0xcca9: 'ECDHE-ECDSA-CHACHA20-POLY1305',
    0xc009: 'ECDHE-ECDSA-AES128-SHA',
    0xc00a: 'ECDHE-ECDSA-AES256-SHA',
    0xc023: 'ECDHE-ECDSA-AES128-SHA256',
    0xc024: 'ECDHE-ECDSA-AES256-SHA384',

    // TLS 1.2 ECDHE+RSA
    0xc02f: 'ECDHE-RSA-AES128-GCM-SHA256',
    0xc030: 'ECDHE-RSA-AES256-GCM-SHA384',
    0xcca8: 'ECDHE-RSA-CHACHA20-POLY1305',
    0xc013: 'ECDHE-RSA-AES128-SHA',
    0xc014: 'ECDHE-RSA-AES256-SHA',
    0xc027: 'ECDHE-RSA-AES128-SHA256',
    0xc028: 'ECDHE-RSA-AES256-SHA384',

    // TLS 1.2 ECDHE+ECDSA CCM/ARIA
    0xc0ac: 'ECDHE-ECDSA-AES128-CCM',
    0xc0ad: 'ECDHE-ECDSA-AES256-CCM',
    0xc05c: 'ECDHE-ECDSA-ARIA128-GCM-SHA256',
    0xc05d: 'ECDHE-ECDSA-ARIA256-GCM-SHA384',

    // TLS 1.2 ECDHE+RSA ARIA
    0xc060: 'ECDHE-ARIA128-GCM-SHA256',
    0xc061: 'ECDHE-ARIA256-GCM-SHA384',

    // TLS 1.2 DHE+RSA
    0x009e: 'DHE-RSA-AES128-GCM-SHA256',
    0x009f: 'DHE-RSA-AES256-GCM-SHA384',
    0xccaa: 'DHE-RSA-CHACHA20-POLY1305',
    0x0033: 'DHE-RSA-AES128-SHA',
    0x0039: 'DHE-RSA-AES256-SHA',
    0x0067: 'DHE-RSA-AES128-SHA256',
    0x006b: 'DHE-RSA-AES256-SHA256',

    // TLS 1.2 DHE+RSA CCM/ARIA
    0xc09e: 'DHE-RSA-AES128-CCM',
    0xc09f: 'DHE-RSA-AES256-CCM',
    0xc052: 'DHE-RSA-ARIA128-GCM-SHA256',
    0xc053: 'DHE-RSA-ARIA256-GCM-SHA384',

    // TLS 1.2 DHE+DSS
    0x00a2: 'DHE-DSS-AES128-GCM-SHA256',
    0x00a3: 'DHE-DSS-AES256-GCM-SHA384',
    0x0032: 'DHE-DSS-AES128-SHA',
    0x0038: 'DHE-DSS-AES256-SHA',
    0x0040: 'DHE-DSS-AES128-SHA256',
    0x006a: 'DHE-DSS-AES256-SHA256',
    0xc056: 'DHE-DSS-ARIA128-GCM-SHA256',
    0xc057: 'DHE-DSS-ARIA256-GCM-SHA384',

    // TLS 1.2 RSA (no PFS)
    0x009c: 'AES128-GCM-SHA256',
    0x009d: 'AES256-GCM-SHA384',
    0x002f: 'AES128-SHA',
    0x0035: 'AES256-SHA',
    0x003c: 'AES128-SHA256',
    0x003d: 'AES256-SHA256',

    // TLS 1.2 RSA CCM/ARIA
    0xc09c: 'AES128-CCM',
    0xc09d: 'AES256-CCM',
    0xc050: 'ARIA128-GCM-SHA256',
    0xc051: 'ARIA256-GCM-SHA384',

    // TLS 1.2 3DES (legacy — Safari still sends these)
    0xc008: 'ECDHE-ECDSA-DES-CBC3-SHA',
    0xc012: 'ECDHE-RSA-DES-CBC3-SHA',
    0x000a: 'DES-CBC3-SHA',
    0x0016: 'EDH-RSA-DES-CBC3-SHA',
};

/** Supported group IANA ID → OpenSSL curve name */
const GROUP_NAMES: Record<number, string> = {
    0x11ec: 'X25519MLKEM768',
    0x001d: 'X25519',
    0x0017: 'P-256',
    0x0018: 'P-384',
    0x0019: 'P-521',
    0x001e: 'X448',
    0x0100: 'ffdhe2048',
    0x0101: 'ffdhe3072',
    0x0102: 'ffdhe4096',
    0x0103: 'ffdhe6144',
    0x0104: 'ffdhe8192',
};

/** Signature algorithm IANA ID → OpenSSL sigalg name */
const SIGALG_NAMES: Record<number, string> = {
    0x0401: 'rsa_pkcs1_sha256',
    0x0501: 'rsa_pkcs1_sha384',
    0x0601: 'rsa_pkcs1_sha512',
    0x0403: 'ecdsa_secp256r1_sha256',
    0x0503: 'ecdsa_secp384r1_sha384',
    0x0603: 'ecdsa_secp521r1_sha512',
    0x0804: 'rsa_pss_rsae_sha256',
    0x0805: 'rsa_pss_rsae_sha384',
    0x0806: 'rsa_pss_rsae_sha512',
    0x0807: 'ed25519',
    0x0808: 'ed448',
    0x0809: 'rsa_pss_pss_sha256',
    0x080a: 'rsa_pss_pss_sha384',
    0x080b: 'rsa_pss_pss_sha512',
    0x081a: 'ecdsa_brainpoolP256r1tls13_sha256',
    0x081b: 'ecdsa_brainpoolP384r1tls13_sha384',
    0x081c: 'ecdsa_brainpoolP512r1tls13_sha512',
    0x0904: 'mldsa44',
    0x0905: 'mldsa65',
    0x0906: 'mldsa87',
    0x0201: 'rsa_pkcs1_sha1',
    0x0203: 'ecdsa_sha1',
    0x0301: 'rsa_pkcs1_sha224',
    0x0302: 'dsa_sha224',
    0x0303: 'ecdsa_sha224',
    0x0402: 'dsa_sha256',
    0x0502: 'dsa_sha384',
    0x0602: 'dsa_sha512',
};

const SHA1_SIGALG_IDS = new Set([0x0201, 0x0203]);

/** Cipher IDs that require @SECLEVEL=0 (3DES, RC4, etc.) */
const LEGACY_CIPHER_IDS = new Set([0xc008, 0xc012, 0x000a, 0x0016]);

// ─── Types ───────────────────────────────────────────────────────────────────

export interface ClientHelloSpec {
    /** All cipher suite IDs in wire order, including GREASE and TLS 1.3 */
    cipherSuites: number[];

    /** All extensions in wire order, including GREASE.
     *  data is required for non-predefined extensions (OpenSSL rejects custom exts without it).
     *  data is ignored for predefined extensions (OpenSSL generates their content).
     *  For known custom exts (e.g. SCT=18), a sensible default is used if data is omitted. */
    extensions: Array<{ type: number; data?: Buffer }>;

    /** Supported group IDs in wire order, including GREASE */
    supportedGroups: number[];

    /** Signature algorithm IDs in wire order */
    signatureAlgorithms: number[];

    /** EC point formats. Defaults to [0] (uncompressed) if omitted.
     *  Note: OpenSSL controls EC point format encoding; this field is best-effort. */
    ecPointFormats?: number[];

    /** ALPN protocol names (e.g. ['h2', 'http/1.1']).
     *  Extracted from the spec into connectOptions. */
    alpnProtocols?: string[];
}

export interface ImpersonateResult {
    secureContext: tls.SecureContext;
    connectOptions: {
        ALPNProtocols?: string[];
        requestOCSP?: boolean;
    };
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

/** Check if a value is a GREASE value (0x?a?a pattern) */
function isGreaseValue(id: number): boolean {
    return (id & 0x0f0f) === 0x0a0a;
}

/** Generate a random GREASE ECH payload */
function generateGreaseEchPayload(): Buffer {
    return Buffer.from([
        0xfe, 0x0d, // ECH version
        0x00,       // ECH type: outer
        0x01,       // config_id
        0x00, 0x20, // KEM id: DHKEM(X25519, HKDF-SHA256)
        0x00, 0x20, // enc length: 32 bytes
        ...crypto.randomBytes(32),
        0x00, 0x10, // payload length: 16 bytes
        ...crypto.randomBytes(16),
    ]);
}

/** Get default extension data for known extension types where data is optional */
function getDefaultExtensionData(type: number): Buffer | undefined {
    if (isGreaseValue(type)) return Buffer.from([0x00]);
    switch (type) {
        case 18: return Buffer.alloc(0); // SCT: empty
        case 28: return Buffer.from([0x40, 0x01]); // record_size_limit: 16385
        case 34: return Buffer.from([ // delegated_credentials: common Firefox scheme list
            0x00, 0x08, 0x04, 0x03, 0x05, 0x03, 0x06, 0x03, 0x02, 0x03,
        ]);
        case 17613: return Buffer.from([0x00, 0x02, 0x68, 0x32]); // ALPS: "h2"
        case 65037: return generateGreaseEchPayload(); // ECH GREASE
        default: return undefined;
    }
}

/** Parse certificate compression algorithm IDs from ext 27 data (RFC 8879) */
function parseCertCompressionAlgorithms(data: Buffer): number[] {
    if (data.length < 3) return [2]; // Default to brotli
    const algLen = data[0];
    const algorithms: number[] = [];
    for (let i = 1; i + 1 <= data.length && algorithms.length * 2 < algLen; i += 2) {
        algorithms.push(data.readUInt16BE(i));
    }
    return algorithms.length > 0 ? algorithms : [2];
}

// Extension type constants for config-driven handling
const EXT_STATUS_REQUEST = 5;
const EXT_ENCRYPT_THEN_MAC = 22;
const EXT_COMPRESS_CERTIFICATE = 27;
const EXT_POST_HANDSHAKE_AUTH = 49;

// ─── Main Function ───────────────────────────────────────────────────────────

/**
 * Create a TLS SecureContext that impersonates the given ClientHello specification.
 *
 * Takes a ClientHelloSpec (typically from a captured ClientHello) and reproduces
 * the TLS fingerprint as closely as possible using OpenSSL's available APIs.
 */
export function impersonate(
    spec: ClientHelloSpec,
    options?: tls.SecureContextOptions
): ImpersonateResult {
    // 1. Map cipher suites to OpenSSL names, preserving order
    const tls13Ciphers: string[] = [];
    const tls12Ciphers: string[] = [];
    let wantScsv = false;
    let hasLegacyCipher = false;
    for (const id of spec.cipherSuites) {
        if (isGreaseValue(id)) continue; // GREASE ciphers can't be added to OpenSSL
        if (id === 0x00ff || id === 0x5600) {
            // SCSV values — OpenSSL adds these automatically under certain conditions.
            // We track the request and configure minVersion/secLevel to trigger it.
            wantScsv = true;
            continue;
        }
        const name = CIPHER_NAMES[id];
        if (!name) {
            console.warn(`tls-impersonate: unknown cipher suite 0x${id.toString(16).padStart(4, '0')}, skipping`);
            continue;
        }
        if (LEGACY_CIPHER_IDS.has(id)) hasLegacyCipher = true;
        if (id >= 0x1300 && id <= 0x13ff) {
            tls13Ciphers.push(name);
        } else {
            tls12Ciphers.push(name);
        }
    }

    // 2. Map supported groups to OpenSSL curve names, preserving order
    const groups: string[] = [];
    for (const id of spec.supportedGroups) {
        if (isGreaseValue(id)) continue; // GREASE groups can't be added to OpenSSL
        const name = GROUP_NAMES[id];
        if (!name) {
            console.warn(`tls-impersonate: unknown supported group 0x${id.toString(16).padStart(4, '0')}, skipping`);
            continue;
        }
        groups.push(name);
    }

    // 3. Map signature algorithms to OpenSSL names, preserving order
    const sigalgs: string[] = [];
    let hasSha1 = false;
    for (const id of spec.signatureAlgorithms) {
        const name = SIGALG_NAMES[id];
        if (!name) {
            console.warn(`tls-impersonate: unknown signature algorithm 0x${id.toString(16).padStart(4, '0')}, skipping`);
            continue;
        }
        sigalgs.push(name);
        if (SHA1_SIGALG_IDS.has(id)) hasSha1 = true;
    }

    // 4. Build cipher string
    //    @SECLEVEL=0 is needed for SHA-1 sigalgs, legacy ciphers (3DES),
    //    and to trigger SCSV when the spec includes TLS_EMPTY_RENEGOTIATION_INFO_SCSV.
    const needSecLevel0 = hasSha1 || hasLegacyCipher || wantScsv;
    const cipherString = tls12Ciphers.join(':') + (needSecLevel0 ? ':@SECLEVEL=0' : '');
    const ciphersuitesString = tls13Ciphers.join(':');

    // 5. Scan extensions for config-driven features
    const extTypes = new Set(spec.extensions.map(e => e.type));
    const connectOpts: ImpersonateResult['connectOptions'] = {};

    if (extTypes.has(EXT_STATUS_REQUEST)) {
        connectOpts.requestOCSP = true;
    }
    if (spec.alpnProtocols?.length) {
        connectOpts.ALPNProtocols = spec.alpnProtocols;
    }

    // 6. Create SecureContext with mapped cipher/sigalg/group strings
    //    OpenSSL only adds SCSV (0x00ff) when @SECLEVEL=0 and minVersion <= TLSv1.
    //    We set minVersion='TLSv1' to trigger SCSV inclusion, then immediately
    //    apply SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1 to prevent actual negotiation
    //    of those old versions (the cipher list is already committed at that point).
    const ctx = tls.createSecureContext({
        ...options,
        ciphers: cipherString,
        sigalgs: sigalgs.join(':'),
        ecdhCurve: groups.join(':'),
        minVersion: wantScsv ? 'TLSv1' as tls.SecureVersion : 'TLSv1.2',
        maxVersion: 'TLSv1.3',
    });

    // 6b. Block TLSv1.0/1.1 negotiation while keeping SCSV in the cipher list
    if (wantScsv) {
        setOptions(ctx,
            crypto.constants.SSL_OP_NO_TLSv1 |
            crypto.constants.SSL_OP_NO_TLSv1_1
        );
    }

    // 7. Set TLS 1.3 ciphersuite order (Node.js silently ignores the
    //    ciphersuites option in createSecureContext)
    if (ciphersuitesString) {
        (ctx as any).context.setCipherSuites(ciphersuitesString);
    }

    // 8. Disable encrypt_then_mac if absent from spec
    if (!extTypes.has(EXT_ENCRYPT_THEN_MAC)) {
        setOptions(ctx, crypto.constants.SSL_OP_NO_ENCRYPT_THEN_MAC);
    }

    // 9. Enable post-handshake auth if present in spec
    if (extTypes.has(EXT_POST_HANDSHAKE_AUTH)) {
        enablePostHandshakeAuth(ctx);
    }

    // 10. Enable certificate compression if present in spec
    if (extTypes.has(EXT_COMPRESS_CERTIFICATE)) {
        const ext27 = spec.extensions.find(e => e.type === EXT_COMPRESS_CERTIFICATE);
        const algorithms = ext27?.data
            ? parseCertCompressionAlgorithms(ext27.data)
            : [2]; // Default to brotli
        try {
            enableCompressCertificate(ctx, algorithms);
        } catch {
            // Certificate compression not available in this OpenSSL build
        }
    }

    // 11. Register extensions in spec order
    for (const ext of spec.extensions) {
        if (isPredefinedExtension(ext.type)) {
            // Predefined extensions are handled by OpenSSL via config above.
            // Some (like SCT=18) can still be registered as custom overrides.
            const data = ext.data ?? getDefaultExtensionData(ext.type);
            if (data !== undefined) {
                try {
                    addCustomExtension(ctx, {
                        extensionType: ext.type,
                        context: constants.SSL_EXT_CLIENT_HELLO,
                        data,
                    });
                } catch {
                    // Truly predefined — OpenSSL handles it internally
                }
            }
            continue;
        }

        // Non-predefined: must be added via custom extension API
        const data = ext.data ?? getDefaultExtensionData(ext.type);
        if (data === undefined) {
            throw new Error(
                `Extension type ${ext.type} requires data ` +
                `(non-predefined extension with no built-in default)`
            );
        }
        addCustomExtension(ctx, {
            extensionType: ext.type,
            context: constants.SSL_EXT_CLIENT_HELLO,
            data,
        });
    }

    return { secureContext: ctx, connectOptions: connectOpts };
}
