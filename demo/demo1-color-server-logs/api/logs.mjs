import { Router } from 'express';

const router = Router();

router.post('/server', (req, res, next) => req.authMiddleware.requireAuthOrApiKey(req, res, next), async (req, res, next) => {
    try {
        const { message, color: requestedColor } = req.body;
        const logMessage = `[API LOG] User ${req.user.email}: ${message}`;

        // Color mapping
        const colors = {
            'red': '\x1b[31m',
            'green': '\x1b[32m',
            'yellow': '\x1b[33m',
            'blue': '\x1b[34m',
            'magenta': '\x1b[35m',
            'cyan': '\x1b[36m',
            'reset': '\x1b[0m'
        };

        let activeColor = null;

        if (req.authType === 'api_key') {
            const hasScope = (scope) => req.scopes?.includes(scope) || req.scopes?.includes('all');
            
            if (requestedColor && requestedColor !== 'default') {
                if (hasScope(`log:${requestedColor}`)) {
                    activeColor = requestedColor;
                } else {
                    return res.status(403).json({ 
                        error: 'FORBIDDEN', 
                        message: `Access denied: Your API key does not have permission for '${requestedColor}' logs.` 
                    });
                }
            } else {
                // No specific color requested, use first available or default
                const availableColors = Object.keys(colors).filter(c => hasScope(`log:${c}`));
                if (availableColors.length > 0) {
                    activeColor = availableColors[0];
                }
            }
        } else {
            // Session auth
            if (requestedColor === 'red') {
                return req.authMiddleware.requireFreshAuth(req, res, (err) => {
                    if (err) return next(err);
                    console.log(`${colors.red}%s${colors.reset}`, logMessage);
                    res.json({ success: true, logged: 'red' });
                });
            }
            activeColor = requestedColor;
        }

        if (activeColor && colors[activeColor]) {
            console.log(`${colors[activeColor]}%s${colors.reset}`, logMessage);
            res.json({ success: true, logged: activeColor });
        } else {
            // Default or no allowed color
            console.log('[LOG]', logMessage);
            res.json({ success: true, logged: 'default' });
        }
    } catch (err) {
        next(err);
    }
});

export default router;

