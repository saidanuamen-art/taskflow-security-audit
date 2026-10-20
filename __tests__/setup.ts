// Setup global pour les tests Jest
import dotenv from 'dotenv';

// Charger les variables d'environnement (quiet : pas de log dotenv dans la sortie Jest,
// y compris pour le `import "dotenv/config"` de src/main.ts)
process.env.DOTENV_CONFIG_QUIET = 'true';
dotenv.config({ quiet: true });

// Vérifier que les variables critiques sont présentes
if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL must be set for tests');
}

if (!process.env.ADMIN_DATABASE_URL) {
  throw new Error('ADMIN_DATABASE_URL must be set for tests (connexion admin, voir .env.example)');
}

if (!process.env.JWT_SECRET) {
  throw new Error('JWT_SECRET must be set for tests');
}

// Configuration globale
process.env.NODE_ENV = 'test';

// Fermer le pool PostgreSQL à la fin de chaque fichier de test,
// sinon Jest reste bloqué sur des connexions ouvertes.
afterAll(async () => {
  const { pool } = require('../src/common/db');
  const { adminPool } = require('./helpers/test-utils');
  await Promise.all([pool.end(), adminPool.end()]);
});
