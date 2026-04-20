import { AuthManager, SQLiteAdaptor } from './AuthManager.mjs';
import { ERROR, ResourceConflictError, AuthError, ValidationError } from './util/errors.mjs';
import { PERSONAL_SCOPES, SESSION_ONLY_SCOPES } from './util/PersonalScopes.mjs';
import { ContactAdaptor, ConsoleContactAdaptor, SmsContactAdaptor } from './contact-adaptors/index.mjs';
import DatabaseAdaptor from './database-adaptors/DatabaseAdaptor.mjs';
import { ChallengeStore } from './stores/ChallengeStore.mjs';
import authRoutes from './routes.mjs';
import { AuthMiddleware } from './AuthMiddleware.mjs';
import { EasyAuth } from './EasyAuth.mjs';

export default AuthManager;
export {
    AuthManager, SQLiteAdaptor,
    ERROR, ResourceConflictError, AuthError, ValidationError,
    PERSONAL_SCOPES, SESSION_ONLY_SCOPES,
    ContactAdaptor, ConsoleContactAdaptor, SmsContactAdaptor,
    DatabaseAdaptor, ChallengeStore,
    authRoutes, AuthMiddleware, EasyAuth,
};

