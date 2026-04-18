import ContactAdaptor from './ContactAdaptor.mjs';

/**
 * SmsContactAdaptor - Delivers authentication codes via SMS.
 *
 * This is a production-ready stub. Swap in your SMS provider SDK by
 * overriding the `#sendSms` private method.
 *
 * Supported providers (examples):
 *   - Twilio:  `await twilioClient.messages.create({ from, to, body })`
 *   - AWS SNS: `await sns.publish({ PhoneNumber: to, Message: body }).promise()`
 *   - Vonage:  `await vonage.sms.send({ to, from, text: body })`
 *
 * @example
 * import { SmsContactAdaptor } from './contact-adaptors/index.mjs';
 *
 * const authManager = new AuthManager({
 *   contactAdaptors: [
 *     new SmsContactAdaptor(authManager, { from: '+15550001234' })
 *   ],
 * });
 */
export default class SmsContactAdaptor extends ContactAdaptor {
    #from;

    constructor(authManager, config = {}) {
        super(authManager);
        this.#from = config.from || 'AuthService';
    }

    async init() {
        console.log('[SmsContactAdaptor] Initialized (stub mode — no SMS provider configured)');
        return true;
    }

    async checkUserLoginRequirements(userIdentifier) {
        const user = await this.AuthManager.databaseAdapter.findUserByIdentifier(userIdentifier)
            ?? await this.AuthManager.databaseAdapter.retrieveUserAuthData(userIdentifier);

        if (!user) return null;

        return {
            requires_password: !!user.password,
            requires_TOTP: !!user.requires_totp,
            requires_login_code: !!user.requires_login_code,
            userId: user.id,
            email: user.email,
            primaryContact: user.primary_contact ?? user.email,
            primaryContactType: user.primary_contact_type ?? 'phone',
        };
    }

    async sendUserLoginCode(userData, loginCode) {
        const phone = userData.primaryContact ?? userData.phone;
        await this.#sendSms(phone, `Your login code is: ${loginCode}`);
    }

    async sendUserSignupCode(userData, signupCode) {
        const phone = userData.primaryContact ?? userData.phone;
        await this.#sendSms(phone, `Your signup code is: ${signupCode}`);
    }

    async sendUserRecoveryCode(userData, recoveryCode) {
        const phone = userData.primaryContact ?? userData.phone;
        await this.#sendSms(
            phone,
            `Your password reset code is: ${recoveryCode}. It expires in 30 minutes. Do not share it.`
        );
    }

    /**
     * @private
     * Replace with your SMS provider SDK call.
     * @param {string} to - Destination phone number (E.164 format, e.g. +6421000000)
     * @param {string} message - Plain text message body
     */
    async #sendSms(to, message) {
        // ─── STUB ───────────────────────────────────────────────────────────────
        // TODO: Replace this with a real SMS provider. Examples above.
        // ────────────────────────────────────────────────────────────────────────
        if (!to) {
            console.warn('[SmsContactAdaptor] No phone number available — cannot send SMS');
            return;
        }
        console.warn(`[SmsContactAdaptor] STUB — would send SMS to ${to}: "${message}"`);
    }
}
