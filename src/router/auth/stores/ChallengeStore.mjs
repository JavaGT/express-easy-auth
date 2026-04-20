/**
 * ChallengeStore - Base interface for storing authentication challenges.
 * Used for WebAuthn, email verification codes, etc.
 */
export class ChallengeStore {
    /**
     * Store a value with a unique key.
     * @param {string} key
     * @param {any} value
     * @param {number} [ttlMs] - Optional time-to-live in milliseconds
     */
    async set(key, value, ttlMs) {
        throw new Error('Method not implemented.');
    }

    /**
     * Retrieve a value by key.
     * @param {string} key
     * @returns {Promise<any>}
     */
    async get(key) {
        throw new Error('Method not implemented.');
    }

    /**
     * Delete a value by key.
     * @param {string} key
     */
    async delete(key) {
        throw new Error('Method not implemented.');
    }

    /**
     * Store a challenge and its metadata.
     * Alias for set() with semantic naming.
     */
    async storeChallenge(key, challenge, ttlMs) {
        return this.set(key, challenge, ttlMs);
    }

    /**
     * Retrieve and immediately delete a challenge (single-use).
     * IMPORTANT: Custom implementations must make get+delete atomic to prevent
     * race conditions where two concurrent requests both consume the same challenge.
     */
    async consumeChallenge(key) {
        const challenge = await this.get(key);
        if (challenge) {
            await this.delete(key);
        }
        return challenge;
    }
}
