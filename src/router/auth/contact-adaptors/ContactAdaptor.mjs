export default class ContactAdaptor {
    constructor(AuthManager) {
        this.AuthManager = AuthManager;
    }

    /**
     * Initialize the contact adaptor (e.g., connect to SMTP, load templates).
     */
    async init() {
        return true;
    }

    /**
     * Send a signup verification code to the user.
     * @param {Object} userData - Basic user info (email, id, etc).
     * @param {string} signupCode - The code to send.
     */
    async sendUserSignupCode(userData, signupCode) {
        throw new Error('sendUserSignupCode not implemented');
    }

    /**
     * Send a login verification code (MFA) to the user.
     * @param {Object} userData - User record from DB.
     * @param {string} loginCode - The MFA code.
     */
    async sendUserLoginCode(userData, loginCode) {
        throw new Error('sendUserLoginCode not implemented');
    }

    /**
     * Send a password recovery code to the user.
     * @param {Object} userData - User record.
     * @param {string} recoveryCode - Recovery code.
     */
    async sendUserRecoveryCode(userData, recoveryCode) {
        throw new Error('sendUserRecoveryCode not implemented');
    }

    /**
     * Determine what authentication steps this user requires.
     * @param {string} userIdentifier - Email or username.
     * @returns {Object|null} - Auth criteria or null if user not found.
     */
    async checkUserLoginRequirements(userIdentifier) {
        throw new Error('checkUserLoginRequirements not implemented');
    }
}
