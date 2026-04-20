import bcrypt from 'bcryptjs';
import { ValidationError, ERROR } from '../util/errors.mjs';

// Pre-computed hash used for constant-time dummy comparisons when the
// user is not found, preventing user-enumeration via timing.
const DUMMY_HASH = '$2a$10$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW';

/**
 * Handle password hashing and verification using bcryptjs.
 */
export class PasswordService {
    static async hash(password, saltRounds = 10) {
        if (!password) throw new ValidationError(ERROR.invalid_input, 'Password is required for hashing');
        return await bcrypt.hash(password, saltRounds);
    }

    static async compare(password, hash) {
        if (!password || !hash) return false;
        if (!hash.startsWith('$2a$') && !hash.startsWith('$2b$')) {
            throw new Error('Password hash is not a valid bcrypt hash. Database may be corrupted.');
        }
        return await bcrypt.compare(password, hash);
    }

    static validateStrength(password) {
        if (!password || password.length < 8) {
            throw new ValidationError(ERROR.invalid_input, 'Password must be at least 8 characters long');
        }
    }

    /** Perform a constant-time dummy bcrypt compare to prevent user-enumeration timing attacks. */
    static async dummyCompare(password) {
        await bcrypt.compare(password || '', DUMMY_HASH);
    }
}
