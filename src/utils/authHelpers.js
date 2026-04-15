import bcrypt from 'bcrypt';
import { randomBytes } from 'node:crypto';

/**
 * Generate a set of secure, readable recovery codes.
 * Returns { plain: string[], hashed: string[] }
 */
export async function generateRecoveryCodes(count = 10) {
    const codes = [];
    const hashes = [];
    for (let i = 0; i < count; i++) {
        // Generate 8 random bytes -> 16 hex chars -> XXXX-XXXX-XXXX format
        const code = randomBytes(6).toString('hex').toUpperCase().match(/.{4}/g).join('-');
        codes.push(code);
        hashes.push(await bcrypt.hash(code, 10)); // Use lower rounds for recovery codes to speed up batch setup
    }
    return { plain: codes, hashed: hashes };
}

/**
 * Generate a secure alphanumeric reset token.
 */
export function generateResetToken(length = 12) {
    const charset = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // Readable alphanumeric
    let token = '';
    const bytes = randomBytes(length);
    for (let i = 0; i < length; i++) {
        token += charset[bytes[i] % charset.length];
    }
    return token;
}

/**
 * JSON error body: { error: { code, message, details? } }
 * @param {import('express').Response} res
 * @param {number} status
 * @param {{ code: string, message: string, details?: unknown }} err
 */
export function formatAuthError(res, status, { code, message, details }) {
    const error = { code, message };
    if (details !== undefined) error.details = details;
    return res.status(status).json({ error });
}

/**
 * Per-request WebAuthn / public URL resolution.
 * Order: optional getWebAuthnOptions(req); else merge static config with request-derived origin/rpID when missing.
 * @param {import('express').Request} req
 * @returns {{ rpName: string, rpID: string, origin: string }}
 */
export function resolveWebAuthnOptions(req) {
    const custom = req.app.get('getWebAuthnOptions');
    if (typeof custom === 'function') {
        const out = custom(req);
        if (!out?.rpID || !out?.origin) {
            throw new Error('getWebAuthnOptions must return rpID and origin');
        }
        return {
            rpName: out.rpName || 'Auth Server',
            rpID: out.rpID,
            origin: out.origin,
        };
    }

    const config = req.app.get('config');
    if (!config) throw new Error('Server configuration missing');

    const host = req.get('host') || '';
    const derivedOrigin = `${req.protocol || 'http'}://${host}`;
    const derivedHostname = host.split(':')[0] || '';

    const origin = config.origin || derivedOrigin;
    let rpID = config.rpID;
    if (!rpID) {
        try {
            rpID = new URL(origin).hostname;
        } catch {
            rpID = derivedHostname;
        }
    }

    return {
        rpName: config.rpName || 'Auth Server',
        rpID,
        origin,
    };
}

/**
 * Standardized auth response for HTML/JSON clients.
 * @param {import('express').Request} req
 * @param {import('express').Response} res
 * @param {{ status: number, redirect?: string, error?: { code: string, message: string, details?: unknown }, data?: Record<string, unknown> }} opts
 */
export function getAuthResponse(req, res, { status, redirect, error, data = {} }) {
    const isHtml = req.headers.accept?.includes('text/html');
    const errMsg = error?.message || 'Authentication failed';
    if (isHtml) {
        if (status >= 400) {
            const origin = `${req.protocol}://${req.get('host')}`;
            const url = new URL(req.headers.referer || '/', origin);
            url.searchParams.set('error', errMsg);
            return res.redirect(url.toString());
        }
        return res.redirect(redirect || '/');
    }
    if (status >= 400 && error) {
        const body = { ...data, error: { code: error.code, message: error.message } };
        if (error.details !== undefined) body.error.details = error.details;
        return res.status(status).json(body);
    }
    return res.status(status).json(data);
}
