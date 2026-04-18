export const ERROR = {
    user_not_found: { message: 'User not found', code: 401, type: 'USER_NOT_FOUND' },
    user_identifier_required: { message: 'User identifier required', code: 400, type: 'USER_IDENTIFIER_REQUIRED' },
    password_required: { message: 'Password required', code: 400, type: 'PASSWORD_REQUIRED' },
    TOTP_code_required: { message: 'TOTP code required', code: 401, type: 'TOTP_CODE_REQUIRED' },
    login_code_required: { message: 'Login code required', code: 401, type: 'LOGIN_CODE_REQUIRED' },
    invalid_credentials: { message: 'Invalid credentials', code: 401, type: 'INVALID_CREDENTIALS' },
    invalid_totp: { message: 'Invalid TOTP code', code: 401, type: 'INVALID_TOTP' },
    invalid_login_code: { message: 'Invalid login code', code: 401, type: 'INVALID_LOGIN_CODE' },
    session_expired: { message: 'Session expired', code: 401, type: 'SESSION_EXPIRED' },
    invalid_session: { message: 'Invalid session', code: 401, type: 'INVALID_SESSION' },
    api_key_required: { message: 'API key required', code: 401, type: 'API_KEY_REQUIRED' },
    invalid_api_key: { message: 'Invalid API key', code: 401, type: 'INVALID_API_KEY' },
    insufficient_permissions: { message: 'Insufficient permissions', code: 403, type: 'INSUFFICIENT_PERMISSIONS' },
    session_step_up_required: { message: 'Step-Up authentication required', code: 401, type: 'STEP_UP_REQUIRED' },
    scope_exceeds_user_authority: { message: 'Cannot grant scopes you do not possess', code: 403, type: 'SCOPE_EXCEEDS_USER_AUTHORITY' },
    invalid_scope: { message: 'Invalid or unknown scope', code: 400, type: 'INVALID_SCOPE' },
    insufficient_scope: { message: 'Insufficient scope for this action', code: 403, type: 'INSUFFICIENT_SCOPE' },
    server_error: { message: 'Internal server error', code: 500, type: 'SERVER_ERROR' },
    resource_conflict: { message: 'Resource already exists', code: 409, type: 'RESOURCE_CONFLICT' }
};

/**
 * Base error class for authentication failures.
 */
export class AuthError extends Error {
    constructor(errorConfig, customMessage) {
        const config = errorConfig || ERROR.server_error;
        super(customMessage || config.message);
        this.code = config.code;
        this.type = config.type;
        this.name = this.constructor.name;
    }

    /**
     * Helper to return consistent error body.
     */
    toJSON() {
        return {
            success: false,
            error: this.type,
            message: this.message,
            code: this.code
        };
    }
}

/**
 * Specifically for input/business logic validation failures.
 */
export class ValidationError extends AuthError {
    constructor(errorConfig, customMessage) {
        super(errorConfig, customMessage);
    }
}

/**
 * Thrown when a create/upsert operation conflicts with an existing resource.
 * Maps to HTTP 409 Conflict. Adaptor layers use this to wrap database
 * unique-constraint violations before they escape into the HTTP layer.
 */
export class ResourceConflictError extends AuthError {
    constructor(customMessage) {
        super(ERROR.resource_conflict, customMessage);
    }
}

