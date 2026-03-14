import { handle } from 'hono/cloudflare-pages';
import app from '../src/index';

export const onRequest = handle(app);
