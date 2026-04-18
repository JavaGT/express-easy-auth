import { ERROR } from '../util/errors.mjs';
import MultiError from '../util/MultiError.mjs';

/**
 * Validates login inputs and specific business logic requirements.
 */
export class LoginValidationService {
    #userIdentifier;
    #userPassword;
    #totpCode;
    #loginCode;

    /**
     * Validate structure of login request body.
     */
    validateLoginInput(userIdentifier, userPassword, totpCode, loginCode) {
        this.#userIdentifier = userIdentifier;
        this.#userPassword = userPassword;
        this.#totpCode = totpCode;
        this.#loginCode = loginCode;

        const errors = new MultiError();

        if (!this.#userIdentifier) {
            errors.add({ ...ERROR.user_identifier_required, field: 'userIdentifier' });
        }
        if (!this.#userPassword) {
            errors.add({ ...ERROR.password_required, field: 'password' });
        }

        if (errors.count > 0) {
            throw errors;
        }

        return {
            userIdentifier: this.#userIdentifier,
            userPassword: this.#userPassword,
            totpCode: this.#totpCode,
            loginCode: this.#loginCode
        };
    }

    /**
     * Validate that MFA requirements are met for the specific user.
     */
    validateLoginRequirements(userLoginRequirements, totpCode, loginCode) {
        const errors = new MultiError();

        if (!userLoginRequirements) {
            errors.add({ ...ERROR.user_not_found, field: 'userIdentifier' });
            return errors;
        }

        // Check TOTP requirement
        if (userLoginRequirements.requires_TOTP && !totpCode) {
            errors.add({ ...ERROR.TOTP_code_required, field: 'totpCode' });
        }

        // Check login code requirement
        if (userLoginRequirements.requires_login_code && !loginCode) {
            errors.add({ ...ERROR.login_code_required, field: 'loginCode' });
        }

        return errors;
    }
}
