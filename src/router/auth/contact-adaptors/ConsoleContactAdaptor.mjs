import ContactAdaptor from './ContactAdaptor.mjs';

export default class ConsoleContactAdaptor extends ContactAdaptor {
    async init() {
        console.log('ConsoleContactAdaptor initialized');
        return true;
    }

    async checkUserLoginRequirements(userIdentifier) {
        // Use findUserByIdentifier to support email, phone, or username
        const user = await this.AuthManager.databaseAdapter.findUserByIdentifier(userIdentifier)
            // Fall back to the old email-only lookup for backward compatibility
            ?? await this.AuthManager.databaseAdapter.retrieveUserAuthData(userIdentifier);

        if (!user) {
            return null;
        }
        return {
            requires_password: !!user.password,
            requires_TOTP: !!user.requires_totp,
            requires_login_code: !!user.requires_login_code,
            userId: user.id,
            email: user.email,
            primaryContact: user.primary_contact ?? user.email,
            primaryContactType: user.primary_contact_type ?? 'email',
        };
    }

    async sendUserSignupCode(userData, signupCode) {
        console.log(`[Signup Code]`);
        console.log(`--------------------------------`);
        console.log(`To: ${userData.email}`);
        console.log(`Subject: Your signup code`);
        console.log(`--------------------------------`);
        console.log(`Your signup code is: ${signupCode}`);
        console.log(`--------------------------------`);
        return signupCode;
    }

    async sendUserLoginCode(userData, loginCode) {
        const to = userData.primaryContact ?? userData.email ?? '(unknown)';
        console.log(`[Login Code]`);
        console.log(`--------------------------------`);
        console.log(`To: ${to}`);
        console.log(`Subject: Your login code`);
        console.log(`--------------------------------`);
        console.log(`Your login code is: ${loginCode}`);
        console.log(`--------------------------------`);
        return loginCode;
    }

    async sendUserRecoveryCode(userData, recoveryCode) {
        const to = userData.primaryContact ?? userData.email ?? '(unknown)';
        console.log(`[Recovery Code]`);
        console.log(`--------------------------------`);
        console.log(`To: ${to}`);
        console.log(`Subject: Your recovery code`);
        console.log(`--------------------------------`);
        console.log(`Your recovery code is: ${recoveryCode}`);
        console.log(`--------------------------------`);
        return recoveryCode;
    }
}
