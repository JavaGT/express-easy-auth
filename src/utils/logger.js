import { randomUUID } from 'crypto';
import { authDb } from '../db/init.js';

/**
 * Base Logger Interface (Concept)
 */
export class Logger {
  error(message, metadata) {}
  warn(message, metadata) {}
  info(message, metadata) {}
  debug(message, metadata) {}
}

/**
 * Default implementation that logs to Console and SQLite
 */
export class DefaultLogger extends Logger {
  constructor(options = {}) {
    super();
    this.console = options.console !== undefined ? options.console : true;
    this.db = options.db !== undefined ? options.db : true;
  }

  error(message, metadata = {}) {
    if (this.console) {
      console.error(`[error] ${message}`, metadata.err || '');
    }
    if (this.db) {
      this._logToDb('error', message, metadata);
    }
  }

  warn(message, metadata = {}) {
    if (this.console) console.warn(`[warn] ${message}`, metadata);
    if (this.db) this._logToDb('warn', message, metadata);
  }

  info(message, metadata = {}) {
    if (this.console) console.info(`[info] ${message}`, metadata);
    if (this.db) this._logToDb('info', message, metadata);
  }

  debug(message, metadata = {}) {
    if (this.console) console.debug(`[debug] ${message}`, metadata);
    // Usually don't log debug to DB unless specified, to save space
  }

  _logToDb(level, message, metadata) {
    try {
      if (authDb) {
        const { err, source = 'server', context = {}, userId = null } = metadata;
        
        authDb.prepare(`
          INSERT INTO system_logs (id, level, source, message, stack, context, user_id, timestamp)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        `).run(
          randomUUID(),
          level,
          source,
          message,
          err?.stack || null,
          JSON.stringify(context),
          userId,
          Date.now()
        );
      }
    } catch (logErr) {
      console.error('[critical] Failed to write to system_logs:', logErr);
    }
  }
}
