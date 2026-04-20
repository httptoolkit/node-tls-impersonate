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

    enableCompressCertificate(nativeCtx: object, algorithms: number[]): void;
    enablePostHandshakeAuth(nativeCtx: object): void;
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
 * Get the native OpenSSL context object from a SecureContext.
 */
function getNativeCtx(ctx: tls.SecureContext): object {
    return (ctx as any).context;
}

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
        getNativeCtx(ctx),
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
    binding.enableCompressCertificate(getNativeCtx(ctx), algorithms);
}

/**
 * Enable post-handshake authentication on a SecureContext.
 * Causes the post_handshake_auth extension (49) to be sent in ClientHello.
 */
export function enablePostHandshakeAuth(ctx: tls.SecureContext): void {
    binding.enablePostHandshakeAuth(getNativeCtx(ctx));
}

/**
 * Set SSL_CTX options. Uses SSL_CTX_set_options which ORs the provided
 * flags with existing options.
 */
export function setOptions(ctx: tls.SecureContext, options: number): void {
    binding.setOptions(getNativeCtx(ctx), options);
}

/**
 * Clear SSL_CTX options.
 */
export function clearOptions(ctx: tls.SecureContext, options: number): void {
    binding.clearOptions(getNativeCtx(ctx), options);
}
