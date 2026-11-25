import type { Hono } from 'hono';
import {
  onRequestPost as evaluatePrPost,
  type DevSecOpsEnv
} from '../functions/api/devsecops-gatekeeper/evaluate-pr';
import type { KVNamespace } from './kvAdapter';
import { createBaseLabApp, verifyRouterSecret, type BaseCloudRunEnv } from './runtime';

export { verifyRouterSecret };

export interface CloudRunEnv extends DevSecOpsEnv, BaseCloudRunEnv {}

export function createCloudRunApp(options?: {
  env?: CloudRunEnv;
  kv?: KVNamespace;
}): Hono {
  return createBaseLabApp<CloudRunEnv>({
    labSlug: 'devsecops-gatekeeper',
    env: options?.env,
    kv: options?.kv,
    registerRoutes: (app, wrap) => {
      app.post('/api/devsecops-gatekeeper/evaluate-pr', wrap(evaluatePrPost));
    }
  });
}
