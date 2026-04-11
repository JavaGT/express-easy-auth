import bcrypt from 'bcrypt';
import { randomBytes } from 'crypto';

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
 * Standardized auth response for HTML/JSON clients.
 */
export function getAuthResponse(req, res, { status, data, redirect }) {
    const isHtml = req.headers.accept?.includes('text/html');
    if (isHtml) {
        if (status >= 400) {
            const origin = `${req.protocol}://${req.get('host')}`;
            const url = new URL(req.headers.referer || '/', origin);
            url.searchParams.set('error', data.error || 'Authentication failed');
            return res.redirect(url.toString());
        }
        return res.redirect(redirect || '/');
    }
    return res.status(status).json(data);
}
