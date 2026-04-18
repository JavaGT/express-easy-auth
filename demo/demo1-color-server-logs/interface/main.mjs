import { Router } from 'express';

const router_interface = Router({ prefix: '/' });
router_interface.get('/', (req, res) => {
    res.send('Hello World');
});

export default router_interface;