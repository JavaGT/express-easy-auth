import { Router } from 'express';
const router_api = Router({ prefix: '/api/v1' });

import router_auth from './auth.mjs';
import router_logs from './logs.mjs';
import router_keys from './keys.mjs';

router_api.use('/auth', router_auth);
router_api.use('/logs', router_logs);
router_api.use('/keys', router_keys);

export default router_api;