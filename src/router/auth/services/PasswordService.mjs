import bcrypt from 'bcryptjs';

/**
 * Handle password hashing and verification using bcryptjs.
 */
export class PasswordService {
    /**
     * Create a secure hash for a password.
     * @param {string} password - Plain text password.
     * @param {number} saltRounds - Cost factor (default 10).
     * @returns {Promise<string>} - Hashed password.
     */
    static async hash(password, saltRounds = 10) {
        if (!password) throw new Error('Password is required for hashing');
        return await bcrypt.hash(password, saltRounds);
    }

    /**
     * Compare a plain text password with a stored hash.
     * @param {string} password - Plain text password.
     * @param {string} hash - Stored bcrypt hash.
     * @returns {Promise<boolean>} - True if match.
     */
    static async compare(password, hash) {
        if (!password || !hash) return false;
        
        // Basic check for plain-text (if it doesn't look like a bcrypt hash)
        // This is a safety check for the transition period.
        if (!hash.startsWith('$2a$') && !hash.startsWith('$2b$')) {
            console.warn('[PasswordService] Comparing against plain-text or unknown hash format. This is insecure.');
            return password === hash;
        }

        return await bcrypt.compare(password, hash);
    }

    /**
     * Basic password strength validation.
     * @param {string} password
     * @throws {Error} - If password is too weak.
     */
    static validateStrength(password) {
        if (!password || password.length < 8) {
            throw new Error('Password must be at least 8 characters long');
        }
        // Additional rules could be added here (regex, etc)
    }
}
