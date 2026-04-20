import { ERROR } from '../util/errors.mjs';
import { TotpService, PasswordService } from './index.mjs';

export class AuthenticationValidator {
    #databaseAdapter;

    constructor(databaseAdapter) {
        this.#databaseAdapter = databaseAdapter;
    }

    async verifyPassword(userIdentifier, userPassword, errors) {
        const passwordHash = await this.#databaseAdapter.retrieveUserPasswordHash(userIdentifier);
        if (!passwordHash) {
            errors.add({ ...ERROR.invalid_credentials, field: 'password' });
            return;
        }
        const isMatch = await PasswordService.compare(userPassword, passwordHash.hash);
        if (!isMatch) {
            errors.add({ ...ERROR.invalid_credentials, field: 'password' });
        }
    }

    async verifyTotp(userLoginRequirements, totpCode, errors) {
        if (!userLoginRequirements.requires_TOTP) return;

        if (!totpCode) {
            errors.add({ ...ERROR.TOTP_code_required, field: 'totpCode' });
            return;
        }

        const user = await this.#databaseAdapter.getUserById(userLoginRequirements.userId);
        if (!user || !user.totp_secret) {
            errors.add({ ...ERROR.invalid_totp, field: 'totpCode' });
            return;
        }

        const totpService = new TotpService();
        const isValid = await totpService.verifyToken(user.totp_secret, totpCode);
        if (!isValid) {
            errors.add({ ...ERROR.invalid_totp, field: 'totpCode' });
        }
    }

    async verifyLoginCode(userLoginRequirements, loginCode, errors) {
        if (!userLoginRequirements.requires_login_code) return;
        // Login code delivery is not yet implemented; always reject.
        errors.add({ ...ERROR.invalid_login_code, field: 'loginCode' });
    }
}
