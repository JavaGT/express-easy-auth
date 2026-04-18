import { ERROR } from '../util/errors.mjs';
import { TotpService, PasswordService } from './index.mjs';

export class AuthenticationValidator {
    #databaseAdapter;

    constructor(databaseAdapter) {
        this.#databaseAdapter = databaseAdapter;
    }

    async verifyPassword(userIdentifier, userPassword, errors) {
        console.log(`[AuthenticationValidator] Verifying password for: ${userIdentifier}`);
        const passwordHash = await this.#databaseAdapter.retrieveUserPasswordHash(userIdentifier);
        
        if (!passwordHash) {
            console.warn(`[AuthenticationValidator] No password hash found for: ${userIdentifier}`);
            errors.add({ ...ERROR.invalid_credentials, field: 'password' });
            return;
        }

        const isMatch = await PasswordService.compare(userPassword, passwordHash.hash);

        if (!isMatch) {
            console.warn(`[AuthenticationValidator] Password mismatch for: ${userIdentifier}`);
            errors.add({ ...ERROR.invalid_credentials, field: 'password' });
        } else {
            console.log(`[AuthenticationValidator] Password verified for: ${userIdentifier}`);
        }
    }

    async verifyTotp(userLoginRequirements, totpCode, errors) {
        if (!userLoginRequirements.requires_TOTP) {
            return;
        }

        if (!totpCode) {
            console.warn(`[AuthenticationValidator] TOTP required but not provided for userId: ${userLoginRequirements.userId}`);
            errors.add({ ...ERROR.TOTP_code_required, field: 'totpCode' });
            return;
        }

        console.log(`[AuthenticationValidator] Verifying TOTP for userId: ${userLoginRequirements.userId}`);
        const user = await this.#databaseAdapter.getUserById(userLoginRequirements.userId);
        if (!user || !user.totp_secret) {
            console.error(`[AuthenticationValidator] User or TOTP secret missing for userId: ${userLoginRequirements.userId}`);
            errors.add({ ...ERROR.invalid_totp, field: 'totpCode' });
            return;
        }

        const totpService = new TotpService();
        const isValid = await totpService.verifyToken(user.totp_secret, totpCode);

        if (!isValid) {
            console.warn(`[AuthenticationValidator] Invalid TOTP code provided for userId: ${userLoginRequirements.userId}`);
            errors.add({ ...ERROR.invalid_totp, field: 'totpCode' });
        } else {
            console.log(`[AuthenticationValidator] TOTP verified for userId: ${userLoginRequirements.userId}`);
        }
    }

    async verifyLoginCode(userLoginRequirements, loginCode, errors) {
        if (!userLoginRequirements.requires_login_code || !loginCode) {
            return;
        }

        // TODO: Implement actual login code verification
        if (loginCode !== '123456') {
            errors.add({ ...ERROR.invalid_login_code, field: 'loginCode' });
        }
    }
}
