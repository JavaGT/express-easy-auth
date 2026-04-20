export default class ContactAdaptor {
    constructor(AuthManager) {
        this.AuthManager = AuthManager;
    }

    async init() {
        return true;
    }

    async sendUserSignupCode(userData, signupCode) {
        throw new Error('sendUserSignupCode not implemented');
    }

    async sendUserLoginCode(userData, loginCode) {
        throw new Error('sendUserLoginCode not implemented');
    }

    async sendUserRecoveryCode(userData, recoveryCode) {
        throw new Error('sendUserRecoveryCode not implemented');
    }
}
