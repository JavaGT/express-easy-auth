import { ChallengeStore } from './ChallengeStore.mjs';

/**
 * InMemoryChallengeStore - Default implementation using a JS Map.
 * Not suitable for multi-instance production environments.
 */
export class InMemoryChallengeStore extends ChallengeStore {
    #store = new Map();
    #timers = new Map();

    async set(key, value, ttlMs) {
        this.#store.set(key, value);

        // Handle TTL
        if (ttlMs) {
            if (this.#timers.has(key)) {
                clearTimeout(this.#timers.get(key));
            }
            const timer = setTimeout(() => {
                this.delete(key);
            }, ttlMs).unref();
            this.#timers.set(key, timer);
        }
    }

    async get(key) {
        return this.#store.get(key);
    }

    async delete(key) {
        this.#store.delete(key);
        if (this.#timers.has(key)) {
            clearTimeout(this.#timers.get(key));
            this.#timers.delete(key);
        }
    }
}
