/**
 * Service for managing Time-based One-Time Passwords (TOTP).
 */
export class TotpService {
    /**
     * Generate a new 20-character base32 secret.
     */
    async generateSecret() {
        try {
            const otplib = await import('otplib');
            return otplib.generateSecret();
        } catch (err) {
            console.error('[TotpService] generateSecret error:', err);
            throw err;
        }
    }

    /**
     * Generate an otpauth:// URI for QR code generation.
     */
    async generateOtpauthUrl(userEmail, secret, issuer = 'Easy Auth Demo') {
        try {
            const otplib = await import('otplib');
            return otplib.generateURI({
                issuer,
                label: userEmail,
                secret
            });
        } catch (err) {
            console.error('[TotpService] generateOtpauthUrl error:', err);
            throw err;
        }
    }

    /**
     * Convert an otpauth URL into a DataURL QR code.
     */
    async generateQrCode(otpauthUrl) {
        try {
            const qrcodeModule = await import('qrcode');
            const QRCode = qrcodeModule.default || qrcodeModule;
            if (!QRCode || typeof QRCode.toDataURL !== 'function') {
                throw new Error('Failed to import QRCode.toDataURL');
            }
            return await QRCode.toDataURL(otpauthUrl);
        } catch (err) {
            console.error('[TotpService] generateQrCode error:', err);
            throw err;
        }
    }

    /**
     * Verify a TOTP token against a secret.
     */
    async verifyToken(secret, token) {
        try {
            const otplib = await import('otplib');
            const result = await otplib.verify({ token, secret, epochTolerance: 30 });
            
            if (result && typeof result === 'object' && 'valid' in result) {
                return result.valid;
            }
            return !!result;
        } catch (err) {
            console.error('[TotpService] verifyToken error:', err);
            throw err;
        }
    }
}
