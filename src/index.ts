import * as tls from 'node:tls';
import * as crypto from 'node:crypto';
import {
    addCustomExtension,
    isPredefinedExtension,
    enableCompressCertificate,
    enablePostHandshakeAuth,
    setCiphersuites,
    getCiphers,
    setOptions,
    setSecurityLevel,
    installSecureSigalgCallback,
    getSSLCtxAvailable,
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
     *  Extracted from the spec into the result's tlsOptions. */
    alpnProtocols?: string[];
}

/** A part of the requested ClientHello that could not be reproduced. The
 *  closest achievable fingerprint is still produced; this just records the gap
 *  so callers can log or monitor it. */
export interface UnsupportedFeature {
    kind: 'cipherSuite' | 'supportedGroup' | 'signatureAlgorithm' | 'extension';
    /** The codepoint from the spec (cipher/group/sigalg id, or extension type). */
    id: number;
    reason: string;
}

export interface ImpersonateResult {
    tlsOptions: {
        secureContext: tls.SecureContext;
        ALPNProtocols?: string[];
        requestOCSP?: boolean;
    };
    /** Spec elements that could not be reproduced, empty when the fingerprint
     *  was reproduced fully. impersonate() never throws for these - it produces
     *  the closest fingerprint it can and records the gaps here. */
    unsupported: UnsupportedFeature[];
}

export interface ImpersonateOptions extends tls.SecureContextOptions {
    /**
     * Emulating some settings requires reducing the OpenSSL security level, which
     * can allow insecure TLS connections. This is disabled by default, but can be
     * enabled with 'insecure' mode here.
     *
     * This isn't required for all insecure features in fingerprints - many can be
     * supported by advertising them but rejecting if used (as many other clients
     * already do) so this is only for specific cases where that's not possible.
     * An issues caused by the default 'secure' mode will be reported in the
     * 'unsupported' result explicitly.
     */
    security?: 'secure' | 'insecure';
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

/** Generate a random ALPN-style protocol name that shouldn't collide with any
 *  existing registration. IANA's longest registered ALPN is ~10 bytes; we
 *  use 16-24 random lowercase-alphanumeric bytes, safely longer than any
 *  real ALPN. Randomized length adds variability per connection. */
function generateGreaseProtocolName(): Buffer {
    const len = 16 + Math.floor(Math.random() * 9); // 16..24
    const charset = 'abcdefghijklmnopqrstuvwxyz0123456789';
    const buf = Buffer.alloc(len);
    for (let i = 0; i < len; i++) {
        buf[i] = charset.charCodeAt(Math.floor(Math.random() * charset.length));
    }
    return buf;
}

/** Build application_settings (ALPS) extension data with a random GREASE
 *  protocol name. ALPS activates only when the server's chosen ALPN matches
 *  a name in this list — long random name shouldn't match any real ALPN
 *  so ALPS should never negotiate. */
function generateAlpsPayload(): Buffer {
    const name = generateGreaseProtocolName();
    const buf = Buffer.alloc(2 + 1 + name.length);
    buf.writeUInt16BE(1 + name.length, 0); // outer list length
    buf.writeUInt8(name.length, 2);        // inner protocol name length
    name.copy(buf, 3);
    return buf;
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
const EXT_EC_POINT_FORMATS = 11;
const EXT_PADDING = 21;
const EXT_ENCRYPT_THEN_MAC = 22;
const EXT_COMPRESS_CERTIFICATE = 27;
const EXT_SESSION_TICKET = 35;
const EXT_POST_HANDSHAKE_AUTH = 49;

// Not exposed in Node's crypto.constants
const SSL_OP_TLSEXT_PADDING = 1 << 4;

/** The ec_point_formats OpenSSL advertises, which it does not let us configure.
 *  OpenSSL < 3.6 sends uncompressed + both compressed [0,1,2]; 3.6+ defaults to
 *  uncompressed only [0]. Detected by version until Node ships an API (or 3.6+)
 *  that lets us set it directly. */
function opensslEcPointFormats(): number[] {
    const match = /^(\d+)\.(\d+)/.exec(process.versions.openssl ?? '');
    const major = match ? Number(match[1]) : 0;
    const minor = match ? Number(match[2]) : 0;
    const atLeast36 = major > 3 || (major === 3 && minor >= 6);
    return atLeast36 ? [0] : [0, 1, 2];
}

// ─── Main Function ───────────────────────────────────────────────────────────

/**
 * Whether TLS impersonation works on this runtime at all: the native addon
 * loaded and Node exposes `node::crypto::GetSSLCtx` (Node >= 24.15). Cheap and
 * global - call it once and fall back to a default fingerprint if it returns
 * false, rather than calling impersonate() and catching its runtime throw.
 *
 * impersonate() still throws on an unsupported runtime as a programmer-error
 * guard; this is how callers avoid hitting it.
 */
export function isSupported(): boolean {
    try {
        return getSSLCtxAvailable();
    } catch {
        // Native addon failed to load at all (wrong platform, build missing, ...).
        return false;
    }
}

/**
 * The parsed-ClientHello shape that clientHelloToSpec / impersonateFromClientHello
 * read. A read-tls-client-hello `TlsClientHelloMessage` satisfies this structurally
 * so you can pass one straight in, but we avoid depending on that explicitly.
 */
export interface ParsedClientHello {
    cipherSuites: number[];
    extensions: Array<{ id: number; data: Record<string, unknown> | null }>;
}

// Extract and cast extension data to the relevant type
function extensionField<T>(hello: ParsedClientHello, extId: number, field: string): T | undefined {
    return hello.extensions.find((ext) => ext.id === extId)?.data?.[field] as T | undefined;
}

/**
 * Convert a parsed ClientHello (from read-tls-client-hello) into a
 * ClientHelloSpec: cipher suites, extension types in wire order, supported
 * groups, signature algorithms, EC point formats and ALPN. GREASE values pass
 * through as-is (impersonate handles them).
 *
 * Extension *data* is not carried over: impersonate regenerates predefined
 * extensions and applies defaults for known custom ones, so the reproduction
 * targets the fingerprint (types and order), not byte-exact custom payloads.
 */
function clientHelloToSpec(hello: ParsedClientHello): ClientHelloSpec {
    return {
        cipherSuites: hello.cipherSuites,
        extensions: hello.extensions.map((ext) => ({ type: ext.id })),
        supportedGroups: extensionField<number[]>(hello, 10, 'groups') ?? [],
        signatureAlgorithms: extensionField<number[]>(hello, 13, 'algorithms') ?? [],
        ecPointFormats: extensionField<number[]>(hello, 11, 'formats'),
        alpnProtocols: extensionField<string[]>(hello, 16, 'protocols'),
    };
}

/**
 * Impersonate a captured ClientHello from read-tls-client-hello directly.
 */
export function impersonateFromClientHello(
    hello: ParsedClientHello,
    options?: ImpersonateOptions
): ImpersonateResult {
    return impersonate(clientHelloToSpec(hello), options);
}

/**
 * Create a TLS SecureContext that impersonates the given ClientHello specification.
 *
 * Takes a ClientHello spec, and reproduces the TLS fingerprint as closely as possible.
 */
export function impersonate(
    spec: ClientHelloSpec,
    options?: ImpersonateOptions
): ImpersonateResult {
    const { security = 'secure', ...secureContextOptions } = options ?? {};

    if (security !== 'secure' && security !== 'insecure') {
        throw new RangeError("security must be 'secure' or 'insecure'");
    }

    const unsupported: UnsupportedFeature[] = [];
    const tls13Ciphers: string[] = [];
    const tls12Ciphers: string[] = [];
    const requestedCipherIds: number[] = [];
    let scsvId: number | undefined;
    for (const id of spec.cipherSuites) {
        if (isGreaseValue(id)) continue;
        if (id === 0x00ff || id === 0x5600) {
            // SCSV values - OpenSSL adds these automatically under certain conditions.
            // We track the request and configure minVersion to trigger it. Keep the
            // first occurrence only, so it maps to a single feature/gap.
            scsvId ??= id;
            continue;
        }
        const name = CIPHER_NAMES[id];
        if (!name) {
            unsupported.push({ kind: 'cipherSuite', id, reason: 'not a known cipher suite' });
            continue;
        }
        requestedCipherIds.push(id);
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
            unsupported.push({ kind: 'supportedGroup', id, reason: 'not a known supported group' });
            continue;
        }
        groups.push(name);
    }

    const sigalgs: string[] = [];
    for (const id of spec.signatureAlgorithms) {
        if (isGreaseValue(id)) continue;
        const name = SIGALG_NAMES[id];
        if (!name) {
            unsupported.push({ kind: 'signatureAlgorithm', id, reason: 'not a known signature algorithm' });
            continue;
        }
        sigalgs.push(name);
    }

    const cipherString = tls12Ciphers.join(':');
    const ciphersuitesString = tls13Ciphers.join(':');

    // Scan extensions for config-driven features
    const extTypes = new Set(spec.extensions.map(e => e.type));
    const connectOpts: Omit<ImpersonateResult['tlsOptions'], 'secureContext'> = {};

    if (extTypes.has(EXT_STATUS_REQUEST)) {
        connectOpts.requestOCSP = true;
    }
    if (spec.alpnProtocols?.length) {
        connectOpts.ALPNProtocols = spec.alpnProtocols;
    }

    // OpenSSL only emits SCSV (0x00ff/0x5600) when at security level 0 with
    // minVersion <= TLSv1, i.e. only in 'insecure' mode. When we can emit it we
    // lower minVersion to trigger inclusion, then block TLSv1.0/1.1 negotiation
    // via SSL_OP flags so the floor stays at TLS 1.2. In 'secure' mode SCSV can't
    // be emitted, so minVersion stays at TLS 1.2 and the gap is reported below.
    const emitScsv = security === 'insecure' && scsvId !== undefined;

    const ctx = tls.createSecureContext({
        ...secureContextOptions,
        ciphers: cipherString,
        sigalgs: sigalgs.join(':'),
        ecdhCurve: groups.join(':'),
        minVersion: emitScsv ? 'TLSv1' as tls.SecureVersion : 'TLSv1.2',
        maxVersion: 'TLSv1.3',
    });

    if (emitScsv) {
        setOptions(ctx,
            crypto.constants.SSL_OP_NO_TLSv1 |
            crypto.constants.SSL_OP_NO_TLSv1_1
        );
    }

    if (security === 'insecure') {
        setSecurityLevel(ctx, 0);
    } else {
        installSecureSigalgCallback(ctx);
        if (scsvId !== undefined) {
            unsupported.push({ kind: 'cipherSuite', id: scsvId,
                reason: "SCSV is only offered in 'insecure' mode" });
        }
    }

    // We build TLS 1.2 and 1.3 cipher strings separately to preserve order,
    // but Node's ciphers option combines them (splitting on TLS_ prefix).
    // Set the TLS 1.3 ciphersuite order independently via the native addon.
    if (ciphersuitesString) {
        setCiphersuites(ctx, ciphersuitesString);
    }

    // Ciphers requested but not compiled into this OpenSSL (e.g. 3DES on
    // OpenSSL 3.5+) are silently dropped from the context. Report the gap.
    const configuredCiphers = new Set(getCiphers(ctx));
    for (const id of requestedCipherIds) {
        if (!configuredCiphers.has(id)) {
            unsupported.push({ kind: 'cipherSuite', id, reason: 'not available in this OpenSSL build' });
        }
    }

    // OpenSSL controls the ec_point_formats content (we cannot set it yet), so
    // a spec asking for a different set than this OpenSSL advertises cannot be
    // reproduced - e.g. Chrome's [0] on OpenSSL < 3.6, which sends [0,1,2].
    if (extTypes.has(EXT_EC_POINT_FORMATS)) {
        const requested = spec.ecPointFormats ?? [0];
        const emitted = opensslEcPointFormats();
        const matches = requested.length === emitted.length &&
            requested.every((f, i) => f === emitted[i]);
        if (!matches) {
            unsupported.push({
                kind: 'extension',
                id: EXT_EC_POINT_FORMATS,
                reason: `ec_point_formats content is controlled by OpenSSL (advertises [${emitted.join(',')}]) and cannot be set`,
            });
        }
    }

    // Padding (RFC 7685) is always reported when requested. OpenSSL decides whether to emit it
    // from the final ClientHello size, so we enable it below but can't really control it.
    if (extTypes.has(EXT_PADDING)) {
        unsupported.push({
            kind: 'extension',
            id: EXT_PADDING,
            reason: 'padding (RFC 7685) is emitted by OpenSSL only for a 256-511 byte ClientHello and cannot be fully controlled',
        });
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
        } catch (e) {
            // Degrade gracefully only when this OpenSSL build lacks certificate
            // compression; surface any other failure (e.g. unsupported runtime).
            if ((e as { code?: string }).code !== 'ERR_CERT_COMPRESSION') throw e;
            unsupported.push({
                kind: 'extension',
                id: EXT_COMPRESS_CERTIFICATE,
                reason: 'certificate compression not available in this OpenSSL build',
            });
        }
    }

    // For server responses to our custom extensions. Servers may echo back
    // extensions (e.g. ECH retry_configs in EncryptedExtensions per RFC 9849,
    // ALPS settings, DC credentials in Certificate, record_size_limit in EE).
    // Without these contexts, OpenSSL rejects the server's response with a
    // "bad extension" error, failing the handshake.
    const customExtContext = constants.SSL_EXT_CLIENT_HELLO
        | constants.SSL_EXT_TLS1_3_SERVER_HELLO
        | constants.SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS
        | constants.SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST
        | constants.SSL_EXT_TLS1_3_CERTIFICATE;

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
                        context: customExtContext,
                        data,
                    });
                } catch (e) {
                    // Only swallow the expected "already handled internally by
                    // OpenSSL" failure; surface anything else.
                    if ((e as { code?: string }).code !== 'ERR_ADD_CUSTOM_EXT') throw e;
                }
            }
            continue;
        }

        const data = ext.data ?? getDefaultExtensionData(ext.type);
        if (data === undefined) {
            unsupported.push({
                kind: 'extension',
                id: ext.type,
                reason: 'non-predefined extension with no data and no built-in default',
            });
            continue;
        }
        try {
            addCustomExtension(ctx, {
                extensionType: ext.type,
                context: customExtContext,
                data,
            });
        } catch (e) {
            if ((e as { code?: string }).code !== 'ERR_ADD_CUSTOM_EXT') throw e;
            unsupported.push({
                kind: 'extension',
                id: ext.type,
                reason: 'OpenSSL rejected the custom extension',
            });
        }
    }

    return { tlsOptions: { secureContext: ctx, ...connectOpts }, unsupported };
}
