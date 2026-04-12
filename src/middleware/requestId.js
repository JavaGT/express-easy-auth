import { randomUUID } from 'node:crypto';

/**
 * Middleware to generate and attach a correlation ID to each request.
 * It also attaches it to the response header.
 */
export function requestId(req, res, next) {
    const headerName = 'X-Correlation-ID';
    const correlationId = req.get(headerName) || randomUUID();
    
    req.id = correlationId;
    req.correlationId = correlationId; // Alias for clarity
    
    res.set(headerName, correlationId);
    next();
}
