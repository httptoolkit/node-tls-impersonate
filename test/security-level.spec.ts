import { expect } from 'chai';
import * as tls from 'node:tls';
import { execFileSync } from 'node:child_process';
import * as os from 'node:os';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { impersonate } from '../src/index.js';
import type { ClientHelloSpec, ImpersonateOptions } from '../src/index.js';
import { getSecurityLevel } from '../src/native.js';
import { captureClientHello } from './test-helpers.js';

const SHA1_SIGALGS = [0x0201, 0x0203];

// A Firefox-shaped spec: modern ciphers/groups but SHA-1 sigalgs. OpenSSL only
// keeps SHA-1 in the offer at security level 0; 'secure' mode restores them via
// a security callback without relaxing what the handshake accepts.
const sha1Spec: ClientHelloSpec = {
    cipherSuites: [0x1301, 0x1302, 0x1303, 0xc02b, 0xc02f, 0x009c],
    extensions: [
        { type: 0 }, { type: 10 }, { type: 13 },
        { type: 43 }, { type: 45 }, { type: 51 },
    ],
    supportedGroups: [0x001d, 0x0017, 0x0018],
    signatureAlgorithms: [0x0403, 0x0804, 0x0401, 0x0503, 0x0203, 0x0201],
};

// Generate a self-signed cert with the given openssl key args, returned as PEMs.
function generateCert(keyArgs: string[]): { key: string; cert: string } {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tls-sec-'));
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

// Handshake against a server presenting `serverCert`, using the given client
// connect options. The cert is trusted as its own CA (so certificate *trust*
// passes and the security level is the only thing that can reject it). Returns
// whether the connection was accepted.
function attemptHandshake(
    serverCert: { key: string; cert: string },
    clientOptions: tls.ConnectionOptions,
): Promise<boolean> {
    return new Promise((resolve, reject) => {
        const server = tls.createServer({ ...serverCert, ciphers: 'DEFAULT:@SECLEVEL=0' });
        server.on('tlsClientError', () => {});
        const done = (result: boolean) => { server.close(); resolve(result); };
        server.listen(0, '127.0.0.1', () => {
            const { port } = server.address() as { port: number };
            const socket = tls.connect(
                { host: '127.0.0.1', port, servername: 'localhost', ...clientOptions },
                () => { socket.destroy(); done(true); },
            );
            socket.on('error', () => { socket.destroy(); done(false); });
        });
        server.on('error', reject);
    });
}

// Whether an impersonated context accepts the server cert.
function connectsTo(serverCert: { key: string; cert: string }, options?: ImpersonateOptions): Promise<boolean> {
    const { secureContext, connectOptions } = impersonate(sha1Spec, { ca: serverCert.cert, ...options });
    return attemptHandshake(serverCert, { secureContext, ...connectOptions });
}

// Whether a plain Node client (no impersonation) accepts the server cert, at
// Node's own default security level. The baseline 'secure' mode must match.
function plainNodeConnectsTo(serverCert: { key: string; cert: string }): Promise<boolean> {
    return attemptHandshake(serverCert, { ca: serverCert.cert });
}

describe('impersonate() security mode', () => {
    let strongCert: { key: string; cert: string };
    let weakCert: { key: string; cert: string };

    before(() => {
        strongCert = generateCert(['-newkey', 'rsa:2048']); // fine at any level
        weakCert = generateCert(['-newkey', 'rsa:1024']);   // ~80-bit: rejected at level >= 2
    });

    it("advertises SHA-1 sigalgs in 'secure' mode (the default)", async () => {
        const { secureContext, connectOptions } = impersonate(sha1Spec);
        const hello = await captureClientHello({ secureContext, ...connectOptions });
        expect(hello.signatureAlgorithms).to.include.members(SHA1_SIGALGS);
    });

    it("advertises SHA-1 sigalgs in 'insecure' mode too", async () => {
        const { secureContext, connectOptions } = impersonate(sha1Spec, { security: 'insecure' });
        const hello = await captureClientHello({ secureContext, ...connectOptions });
        expect(hello.signatureAlgorithms).to.include.members(SHA1_SIGALGS);
    });

    it("'secure' mode reports no sigalg gap (SHA-1 fidelity is preserved)", () => {
        const { unsupported } = impersonate(sha1Spec);
        expect(unsupported.filter((u) => u.kind === 'signatureAlgorithm')).to.deep.equal([]);
    });

    it("'secure' mode leaves the security level at the build default (no downgrade)", () => {
        const { secureContext } = impersonate(sha1Spec);
        expect(getSecurityLevel(secureContext)).to.be.greaterThan(0);
    });

    it("'insecure' mode drops to security level 0", () => {
        const { secureContext } = impersonate(sha1Spec, { security: 'insecure' });
        expect(getSecurityLevel(secureContext)).to.equal(0);
    });

    it("'secure' mode accepts a strong server cert", async () => {
        expect(await connectsTo(strongCert)).to.equal(true);
    });

    it("'secure' mode treats a weak (1024-bit) server cert exactly like a normal Node client", async () => {
        // On every supported runtime (OpenSSL >= 3.2 defaults to level 2) this
        // means rejection; asserting parity keeps the test correct even on a
        // build whose default level differs, since that is the actual guarantee.
        const secureAccepts = await connectsTo(weakCert);
        const plainAccepts = await plainNodeConnectsTo(weakCert);
        expect(secureAccepts).to.equal(plainAccepts);
    });

    it("'insecure' mode accepts the same weak server cert", async () => {
        expect(await connectsTo(weakCert, { security: 'insecure' })).to.equal(true);
    });

    it('rejects an invalid security value', () => {
        // @ts-expect-error - exercising the runtime guard against a bad value
        expect(() => impersonate(sha1Spec, { security: 'lax' })).to.throw(RangeError);
    });
});
