import { ERROR } from '../util/errors.mjs';
import MultiError from '../util/MultiError.mjs';

export class LoginValidationService {
    validateLoginInput(userIdentifier, userPassword, totpCode, loginCode) {
        const errors = new MultiError();

        if (!userIdentifier) {
            errors.add({ ...ERROR.user_identifier_required, field: 'userIdentifier' });
        }
        if (!userPassword) {
            errors.add({ ...ERROR.password_required, field: 'password' });
        }

        if (errors.count > 0) throw errors;

        return { userIdentifier, userPassword, totpCode, loginCode };
    }

    validateLoginRequirements(userLoginRequirements, totpCode, loginCode) {
        const errors = new MultiError();

        if (!userLoginRequirements) {
            errors.add({ ...ERROR.user_not_found, field: 'userIdentifier' });
            return errors;
        }

        if (userLoginRequirements.requires_TOTP && !totpCode) {
            errors.add({ ...ERROR.TOTP_code_required, field: 'totpCode' });
        }

        if (userLoginRequirements.requires_login_code && !loginCode) {
            errors.add({ ...ERROR.login_code_required, field: 'loginCode' });
        }

        return errors;
    }
}
