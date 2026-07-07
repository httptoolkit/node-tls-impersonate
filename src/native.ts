import * as tls from 'node:tls';
import * as path from 'node:path';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);

interface NativeBinding {
    addCustomExtension(
        nativeCtx: object,
        extType: number,
        ctxFlags: number,
        data: Buffer | null,
        add: ((extType: number, context: number) => Buffer | null) | null,
        parse: ((extType: number, context: number, data: Buffer) => boolean) | null
    ): void;

    isPredefinedExtension(extType: number): boolean;
    getSSLCtxAvailable(): boolean;

    enableCompressCertificate(nativeCtx: object, algorithms: number[]): void;
    enablePostHandshakeAuth(nativeCtx: object): void;
    setCiphersuites(nativeCtx: object, ciphersuites: string): void;
    getCiphers(nativeCtx: object): number[];
    setOptions(nativeCtx: object, options: number): void;
    clearOptions(nativeCtx: object, options: number): void;

    constants: {
        SSL_EXT_TLS_ONLY: number;
        SSL_EXT_DTLS_ONLY: number;
        SSL_EXT_TLS_IMPLEMENTATION_ONLY: number;
        SSL_EXT_SSL3_ALLOWED: number;
        SSL_EXT_TLS1_2_AND_BELOW_ONLY: number;
        SSL_EXT_TLS1_3_ONLY: number;
        SSL_EXT_IGNORE_ON_RESUMPTION: number;
        SSL_EXT_CLIENT_HELLO: number;
        SSL_EXT_TLS1_2_SERVER_HELLO: number;
        SSL_EXT_TLS1_3_SERVER_HELLO: number;
        SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS: number;
        SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST: number;
        SSL_EXT_TLS1_3_CERTIFICATE: number;
        SSL_EXT_TLS1_3_NEW_SESSION_TICKET: number;
        SSL_EXT_TLS1_3_CERTIFICATE_REQUEST: number;
        TLSEXT_comp_cert_zlib: number;
        TLSEXT_comp_cert_brotli: number;
        TLSEXT_comp_cert_zstd: number;
    };
}

// Load the native binding. In development it's in build/Release/,
// when published with prebuildify it's found by node-gyp-build.
let binding: NativeBinding;
try {
    // Try node-gyp-build first (for prebuildified releases)
    binding = require('node-gyp-build')(path.resolve(import.meta.dirname, '..'));
} catch {
    // Fall back to build/Release/ (for development)
    binding = require(path.resolve(import.meta.dirname, '..', 'build', 'Release', 'tls_impersonate.node'));
}

export const constants = binding.constants;

/**
 * Add a custom TLS extension to a SecureContext.
 * Only works for extensions not predefined by OpenSSL.
 */
export function addCustomExtension(
    ctx: tls.SecureContext,
    options: {
        extensionType: number;
        context: number;
        data?: Buffer;
        add?: (extType: number, context: number) => Buffer | null;
        parse?: (extType: number, context: number, data: Buffer) => boolean;
    }
): void {
    const hasData = options.data !== undefined;
    const hasAdd = typeof options.add === 'function';

    if (hasData && hasAdd) {
        throw new TypeError('data and add are mutually exclusive');
    }
    if (!hasData && !hasAdd) {
        throw new TypeError('Either data (Buffer) or add (Function) must be provided');
    }

    binding.addCustomExtension(
        ctx,
        options.extensionType,
        options.context,
        hasData ? options.data! : null,
        hasAdd ? options.add! : null,
        options.parse || null,
    );
}

/**
 * Check if an extension type is predefined by OpenSSL
 * (and therefore cannot be added as a custom extension).
 */
export function isPredefinedExtension(extType: number): boolean {
    return binding.isPredefinedExtension(extType);
}

/**
 * Whether node::crypto::GetSSLCtx resolved on this runtime (Node >= 24.15).
 */
export function getSSLCtxAvailable(): boolean {
    return binding.getSSLCtxAvailable();
}

/**
 * Enable certificate compression on a SecureContext.
 * Causes the compress_certificate extension (27) to be sent.
 *
 * Note: Requires OpenSSL to be built with compression support.
 * May throw if the compression algorithms are not available.
 *
 * @param algorithms - Array of compression algorithm IDs in preference order.
 *   Use constants: TLSEXT_comp_cert_zlib (1), TLSEXT_comp_cert_brotli (2), TLSEXT_comp_cert_zstd (3)
 */
export function enableCompressCertificate(
    ctx: tls.SecureContext,
    algorithms: number[]
): void {
    binding.enableCompressCertificate(ctx, algorithms);
}

/**
 * Enable post-handshake authentication on a SecureContext.
 * Causes the post_handshake_auth extension (49) to be sent in ClientHello.
 */
export function enablePostHandshakeAuth(ctx: tls.SecureContext): void {
    binding.enablePostHandshakeAuth(ctx);
}

/**
 * Set the TLS 1.3 ciphersuite list and order (SSL_CTX_set_ciphersuites).
 * Node's `ciphers` option cannot control the TLS 1.3 order independently of
 * the TLS 1.2 cipher list, so this is set directly on the SecureContext.
 */
export function setCiphersuites(ctx: tls.SecureContext, ciphersuites: string): void {
    binding.setCiphersuites(ctx, ciphersuites);
}

/**
 * Return the IANA cipher-suite ids actually configured on the context. Ciphers
 * requested but not compiled into this OpenSSL build (e.g. 3DES) are silently
 * dropped, so this reveals which requested ciphers survived.
 */
export function getCiphers(ctx: tls.SecureContext): number[] {
    return binding.getCiphers(ctx);
}

/**
 * Set SSL_CTX options. Uses SSL_CTX_set_options which ORs the provided
 * flags with existing options.
 */
export function setOptions(ctx: tls.SecureContext, options: number): void {
    binding.setOptions(ctx, options);
}

/**
 * Clear SSL_CTX options.
 */
export function clearOptions(ctx: tls.SecureContext, options: number): void {
    binding.clearOptions(ctx, options);
}
