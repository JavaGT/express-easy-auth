export const PERSONAL_SCOPES = Object.freeze([
    'personal:profile.read',
    'personal:profile.write',
    'personal:auth.read',
    'personal:auth.write',
    'personal:apikeys.read',
    'personal:apikeys.write',
]);

// These scopes require an interactive session. API keys may never declare them.
export const SESSION_ONLY_SCOPES = Object.freeze(['personal:apikeys.write']);
