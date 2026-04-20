export class TotpService {
    #issuer;

    constructor(issuer = 'Easy Auth Demo') {
        this.#issuer = issuer;
    }

    async generateSecret() {
        const otplib = await import('otplib');
        return otplib.generateSecret();
    }

    async generateOtpauthUrl(userEmail, secret, issuer = this.#issuer) {
        const otplib = await import('otplib');
        return otplib.generateURI({ issuer, label: userEmail, secret });
    }

    async generateQrCode(otpauthUrl) {
        const qrcodeModule = await import('qrcode');
        const QRCode = qrcodeModule.default || qrcodeModule;
        if (!QRCode || typeof QRCode.toDataURL !== 'function') {
            throw new Error('Failed to import QRCode.toDataURL');
        }
        return await QRCode.toDataURL(otpauthUrl);
    }

    async verifyToken(secret, token) {
        const otplib = await import('otplib');
        const result = await otplib.verify({ token, secret });
        if (result && typeof result === 'object' && 'valid' in result) return result.valid;
        return !!result;
    }
}
