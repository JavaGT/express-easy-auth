import { ERROR } from '../util/errors.mjs';

/**
 * Service for handles WebAuthn (Passkeys) registration and authentication.
 */
export class WebAuthnService {
    #databaseAdapter;
    #rpName;
    #rpID;
    #origin;

    constructor(databaseAdapter, config = {}) {
        this.#databaseAdapter = databaseAdapter;
        this.#rpName = config.rpName || 'Easy Auth Demo';
        this.#rpID = config.rpID || 'localhost';
        this.#origin = config.origin || 'http://localhost:3000';
    }

    async generateRegistrationOptions(user, reqConfig = {}) {
        const { generateRegistrationOptions } = await import('@simplewebauthn/server');
        const userAuthenticators = await this.#databaseAdapter.getAuthenticatorsByUserId(user.id);

        return await generateRegistrationOptions({
            rpName: reqConfig.rpName || this.#rpName,
            rpID: reqConfig.rpID || this.#rpID,
            userName: user.email,
            userDisplayName: user.display_name || user.email,
            userID: new TextEncoder().encode(user.id.toString()),
            attestationType: 'none',
            excludeCredentials: userAuthenticators.map(auth => ({
                id: auth.credential_id,
                type: 'public-key',
                transports: auth.transports ? JSON.parse(auth.transports) : undefined,
            })),
            authenticatorSelection: {
                residentKey: 'preferred',
                userVerification: 'preferred',
            },
        });
    }

    async verifyRegistration(user, registrationResponse, expectedChallenge, authenticatorName, reqConfig = {}) {
        try {
            const { verifyRegistrationResponse } = await import('@simplewebauthn/server');

            const origin = reqConfig.origin || this.#origin;
            const rpID = reqConfig.rpID || this.#rpID;

            const verification = await verifyRegistrationResponse({
                response: registrationResponse,
                expectedChallenge,
                expectedOrigin: origin,
                expectedRPID: rpID,
            });

            if (verification.verified && verification.registrationInfo) {
                const { id, publicKey, counter, transports } = verification.registrationInfo.credential;
                await this.#databaseAdapter.createAuthenticator(
                    user.id,
                    id,
                    Buffer.from(publicKey),
                    counter,
                    JSON.stringify(transports || registrationResponse.response.transports || []),
                    authenticatorName
                );
            }

            return verification;
        } catch (err) {
            console.error('[WebAuthnService] Registration CRITICAL ERROR:', err);
            throw err;
        }
    }

    async generateAuthenticationOptions(reqConfig = {}) {
        const { generateAuthenticationOptions } = await import('@simplewebauthn/server');

        return await generateAuthenticationOptions({
            rpID: reqConfig.rpID || this.#rpID,
            userVerification: 'preferred',
        });
    }

    async verifyAuthentication(authenticationResponse, expectedChallenge, reqConfig = {}) {
        const { verifyAuthenticationResponse } = await import('@simplewebauthn/server');
        
        const authenticator = await this.#databaseAdapter.getAuthenticatorById(authenticationResponse.id);
        if (!authenticator) {
            throw new Error(ERROR.invalid_credentials.message);
        }

        const origin = reqConfig.origin || this.#origin;
        const rpID = reqConfig.rpID || this.#rpID;

        const verification = await verifyAuthenticationResponse({
            response: authenticationResponse,
            expectedChallenge,
            expectedOrigin: origin,
            expectedRPID: rpID,
            credential: {
                id: authenticator.credential_id,
                publicKey: authenticator.public_key instanceof Uint8Array ? authenticator.public_key : new Uint8Array(authenticator.public_key),
                counter: authenticator.counter,
                transports: authenticator.transports ? JSON.parse(authenticator.transports) : undefined,
            },
        });

        if (verification.verified && verification.authenticationInfo) {
            await this.#databaseAdapter.updateAuthenticatorCounter(
                authenticator.credential_id,
                verification.authenticationInfo.newCounter
            );
        }

        return {
            verified: verification.verified,
            userId: authenticator.user_id
        };
    }
}
