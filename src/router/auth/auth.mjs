import { AuthManager, SQLiteAdaptor } from './AuthManager.mjs';
import { ERROR, ResourceConflictError, AuthError, ValidationError, ValidationError as InputError } from './util/errors.mjs';
import { PERSONAL_SCOPES, SESSION_ONLY_SCOPES } from './util/PersonalScopes.mjs';
import { ContactAdaptor, ConsoleContactAdaptor, SmsContactAdaptor } from './contact-adaptors/index.mjs';
import authRoutes from './routes.mjs';
import { AuthMiddleware } from './AuthMiddleware.mjs';
import { EasyAuth } from './EasyAuth.mjs';

export default AuthManager;
export {
    AuthManager, SQLiteAdaptor,
    ERROR, ResourceConflictError, AuthError, ValidationError,
    PERSONAL_SCOPES, SESSION_ONLY_SCOPES,
    ContactAdaptor, ConsoleContactAdaptor, SmsContactAdaptor,
    authRoutes, AuthMiddleware, EasyAuth,
};

