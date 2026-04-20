import ContactAdaptor from './ContactAdaptor.mjs';

export default class ConsoleContactAdaptor extends ContactAdaptor {
    async init() {
        console.log('ConsoleContactAdaptor initialized');
        return true;
    }

    async sendUserSignupCode(userData, signupCode) {
        const masked = process.env.NODE_ENV === 'production' ? '[REDACTED]' : signupCode;
        console.log(`[Signup Code] To: ${userData.email} | Code: ${masked}`);
        return signupCode;
    }

    async sendUserLoginCode(userData, loginCode) {
        const to     = userData.primaryContact ?? userData.email ?? '(unknown)';
        const masked = process.env.NODE_ENV === 'production' ? '[REDACTED]' : loginCode;
        console.log(`[Login Code] To: ${to} | Code: ${masked}`);
        return loginCode;
    }

    async sendUserRecoveryCode(userData, recoveryCode) {
        const to     = userData.primaryContact ?? userData.email ?? '(unknown)';
        const masked = process.env.NODE_ENV === 'production' ? '[REDACTED]' : recoveryCode;
        console.log(`[Recovery Code] To: ${to} | Code: ${masked}`);
        return recoveryCode;
    }
}
