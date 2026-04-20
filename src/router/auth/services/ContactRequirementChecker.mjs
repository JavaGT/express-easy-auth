import { ERROR } from '../util/errors.mjs';

export class ContactRequirementChecker {
    #databaseAdapter;

    constructor(databaseAdapter) {
        this.#databaseAdapter = databaseAdapter;
    }

    async checkUserLoginRequirements(userIdentifier) {
        if (!userIdentifier) {
            return null;
        }

        const user = await this.#databaseAdapter.retrieveUserAuthData(userIdentifier);
        
        if (!user) {
            return null;
        }

        return {
            requires_password: !!user.password,
            requires_TOTP: !!user.requires_totp,
            requires_login_code: !!user.requires_login_code,
            userId: user.id,
            email: user.email,
            display_name: user.display_name ?? null,
        };
    }
}
