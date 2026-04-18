import { randomBytes } from 'node:crypto';
import { ERROR, AuthError } from '../util/errors.mjs';

/**
 * Handles session lifecycle: creation, validation, and destruction.
 */
export class SessionManager {
    #databaseAdapter;

    constructor(databaseAdapter) {
        this.#databaseAdapter = databaseAdapter;
    }

    /**
     * Create a new session for a user.
     * @param {Object} userLoginRequirements - User data mapping.
     * @returns {Promise<Object>} - sessionToken and sessionExpiresAt.
     */
    async createSession(userLoginRequirements) {
        const sessionToken = this.#generateSessionToken();
        const sessionExpiresAt = this.#calculateSessionExpiry();
        const now = Date.now();

        await this.#databaseAdapter.createSession(
            userLoginRequirements.userId,
            sessionToken,
            sessionExpiresAt,
            now
        );

        return {
            sessionToken,
            sessionExpiresAt
        };
    }

    /**
     * Revoke a specific session.
     */
    async destroySession(sessionToken) {
        await this.#databaseAdapter.deleteSession(sessionToken);
    }

    /**
     * Validate a session token and return user data if valid.
     * @param {string} sessionToken
     * @returns {Promise<Object>} - Augmented session data.
     * @throws {Error} - If session is invalid or expired.
     */
    async validateSession(sessionToken) {
        const session = await this.#databaseAdapter.getSession(sessionToken);

        if (!session) {
            throw new AuthError(ERROR.invalid_session);
        }

        if (Date.now() > session.expires_at) {
            await this.#databaseAdapter.deleteSession(sessionToken);
            throw new AuthError(ERROR.session_expired);
        }

        return {
            user: {
                id: session.user_id,
                email: session.email,
                display_name: session.display_name
            },
            sessionToken,
            lastAuthenticatedAt: session.last_authenticated_at
        };
    }

    /**
     * Generate a cryptographically secure random token.
     * Use node:crypto for server-side security.
     */
    #generateSessionToken() {
        return randomBytes(32).toString('hex');
    }

    #calculateSessionExpiry() {
        return Date.now() + (7 * 24 * 60 * 60 * 1000); // 7 days
    }
}
