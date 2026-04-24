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

/** All 16 GREASE codepoints per RFC 8701 */
const GREASE_VALUES = [
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
];

/** Build delegated_credentials extension data with GREASE sig schemes.
 *  Using GREASE values means servers ignore the advertised schemes, so
 *  the server won't actually send a delegated credential we can't validate.
 *  Picks 3-4 random GREASE codepoints for variability. */
function generateGreaseDelegatedCredentialsPayload(): Buffer {
    const count = 3 + Math.floor(Math.random() * 2); // 3 or 4
    const pool = [...GREASE_VALUES];
    const schemes: number[] = [];
    for (let i = 0; i < count; i++) {
        const idx = Math.floor(Math.random() * pool.length);
        schemes.push(pool.splice(idx, 1)[0]);
    }
    const buf = Buffer.alloc(2 + schemes.length * 2);
    buf.writeUInt16BE(schemes.length * 2, 0);
    for (let i = 0; i < schemes.length; i++) {
        buf.writeUInt16BE(schemes[i], 2 + i * 2);
    }
    return buf;
}

/** Generate a GREASE ECH (encrypted_client_hello) payload matching Chrome/
 *  BoringSSL behavior per RFC 9849 §6.2.
 */
function generateGreaseEchPayload(): Buffer {
    const aead = Math.random() < 0.5 ? 0x0001 : 0x0003; // AES-128-GCM or ChaCha20
    const encLen = 32;
    const payloadBase = 32 * (4 + Math.floor(Math.random() * 4)); // 128, 160, 192, or 224
    const payloadLen = payloadBase + 16; // AEAD tag overhead

    const buf = Buffer.alloc(1 + 4 + 1 + 2 + encLen + 2 + payloadLen);
    let off = 0;
    buf.writeUInt8(0x00, off); off += 1;              // type: outer
    buf.writeUInt16BE(0x0001, off); off += 2;         // KDF: HKDF-SHA256
    buf.writeUInt16BE(aead, off); off += 2;           // AEAD: random
    buf.writeUInt8(crypto.randomBytes(1)[0], off); off += 1; // config_id
    buf.writeUInt16BE(encLen, off); off += 2;
    crypto.randomFillSync(buf, off, encLen); off += encLen;
    buf.writeUInt16BE(payloadLen, off); off += 2;
    crypto.randomFillSync(buf, off, payloadLen);
    return buf;
}

/** Build application_settings (ALPS) extension data with an empty protocol
 *  list. ALPS activates only when the server's chosen ALPN matches a name in
 *  this list, so an empty list guarantees ALPS never negotiates */
function generateAlpsPayload(): Buffer {
    return Buffer.from([0x00, 0x00]); // zero-length protocol list
}

/** Get default extension data for known extension types where data is optional */
function getDefaultExtensionData(type: number): Buffer | undefined {
    if (isGreaseValue(type)) return Buffer.from([0x00]);
    switch (type) {
        case 18: return Buffer.alloc(0); // SCT: empty
        case 28: return Buffer.from([0x40, 0x01]); // record_size_limit: 16385
        case 34: return generateGreaseDelegatedCredentialsPayload();
        case 17613: return generateAlpsPayload();
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
const EXT_PADDING = 21;
const EXT_ENCRYPT_THEN_MAC = 22;
const EXT_COMPRESS_CERTIFICATE = 27;
const EXT_SESSION_TICKET = 35;
const EXT_POST_HANDSHAKE_AUTH = 49;

// Not exposed in Node's crypto.constants
const SSL_OP_TLSEXT_PADDING = 1 << 4;

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
    const tls13Ciphers: string[] = [];
    const tls12Ciphers: string[] = [];
    let wantScsv = false;
    let hasLegacyCipher = false;
    for (const id of spec.cipherSuites) {
        if (isGreaseValue(id)) continue;
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

    const groups: string[] = [];
    for (const id of spec.supportedGroups) {
        if (isGreaseValue(id)) continue;
        const name = GROUP_NAMES[id];
        if (!name) {
            console.warn(`tls-impersonate: unknown supported group 0x${id.toString(16).padStart(4, '0')}, skipping`);
            continue;
        }
        groups.push(name);
    }

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

    // @SECLEVEL=0 is needed for SHA-1 sigalgs, legacy ciphers (3DES),
    // and to trigger SCSV when the spec includes TLS_EMPTY_RENEGOTIATION_INFO_SCSV.
    const needSecLevel0 = hasSha1 || hasLegacyCipher || wantScsv;
    const cipherString = tls12Ciphers.join(':') + (needSecLevel0 ? ':@SECLEVEL=0' : '');
    const ciphersuitesString = tls13Ciphers.join(':');

    // Scan extensions for config-driven features
    const extTypes = new Set(spec.extensions.map(e => e.type));
    const connectOpts: ImpersonateResult['connectOptions'] = {};

    if (extTypes.has(EXT_STATUS_REQUEST)) {
        connectOpts.requestOCSP = true;
    }
    if (spec.alpnProtocols?.length) {
        connectOpts.ALPNProtocols = spec.alpnProtocols;
    }

    // OpenSSL only adds SCSV (0x00ff) when @SECLEVEL=0 and minVersion <= TLSv1.
    // We set minVersion='TLSv1' to trigger SCSV inclusion, then immediately
    // block TLSv1.0/1.1 negotiation via SSL_OP flags.
    const ctx = tls.createSecureContext({
        ...options,
        ciphers: cipherString,
        sigalgs: sigalgs.join(':'),
        ecdhCurve: groups.join(':'),
        minVersion: wantScsv ? 'TLSv1' as tls.SecureVersion : 'TLSv1.2',
        maxVersion: 'TLSv1.3',
    });

    if (wantScsv) {
        setOptions(ctx,
            crypto.constants.SSL_OP_NO_TLSv1 |
            crypto.constants.SSL_OP_NO_TLSv1_1
        );
    }

    // We build TLS 1.2 and 1.3 cipher strings separately to preserve order,
    // but Node's ciphers option combines them (splitting on TLS_ prefix).
    // Call setCipherSuites directly to set the TLS 1.3 order independently.
    if (ciphersuitesString) {
        (ctx as any).context.setCipherSuites(ciphersuitesString);
    }

    if (!extTypes.has(EXT_ENCRYPT_THEN_MAC)) {
        setOptions(ctx, crypto.constants.SSL_OP_NO_ENCRYPT_THEN_MAC);
    }

    if (!extTypes.has(EXT_SESSION_TICKET)) {
        setOptions(ctx, crypto.constants.SSL_OP_NO_TICKET);
    }

    // Enable conditional padding (OpenSSL pads ClientHello to 512 bytes when
    // it would otherwise be 256-511 bytes, per RFC 7685 F5 workaround).
    if (extTypes.has(EXT_PADDING)) {
        setOptions(ctx, SSL_OP_TLSEXT_PADDING);
    }

    if (extTypes.has(EXT_POST_HANDSHAKE_AUTH)) {
        enablePostHandshakeAuth(ctx);
    }

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

    // Register custom extensions. Predefined extensions are handled by OpenSSL
    // via the config above; some (like SCT=18) can still be added as custom
    // overrides if they have data.
    for (const ext of spec.extensions) {
        if (isPredefinedExtension(ext.type)) {
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
