import { Express } from 'express';
import app from '../../src/main';

/**
 * Retourne l'application Express réelle (src/main.ts), sans serveur HTTP.
 *
 * Les tests utilisent exactement les mêmes routes, middlewares et gardes que
 * l'API en production (ex. POST /api/users/change-role avec requireRole(50)).
 * Une copie des routes ici risquerait de diverger et de tester une autre app.
 */
export function createTestApp(): Express {
  return app;
}
