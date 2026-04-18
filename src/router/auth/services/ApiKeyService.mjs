import { ERROR } from '../util/errors.mjs';

/**
 * Service for validating and managing API Keys.
 */
export class ApiKeyService {
    #databaseAdapter;

    constructor(databaseAdapter) {
        this.#databaseAdapter = databaseAdapter;
    }

    /**
     * Validate an API key and return associated user and scopes.
     * @param {string} apiKey
     * @returns {Promise<Object>}
     * @throws {Error} - If key is invalid or expired.
     */
    async validateApiKey(apiKey) {
        const key = await this.#databaseAdapter.getApiKey(apiKey);
        
        if (!key) {
            throw new Error(ERROR.invalid_api_key.message);
        }

        if (key.expires_at && Date.now() > key.expires_at) {
            throw new Error(ERROR.session_expired.message);
        }

        return {
            user: {
                id: key.user_id,
                email: key.email
            },
            scopes: key.scopes ? JSON.parse(key.scopes) : [],
            name: key.name
        };
    }
}
