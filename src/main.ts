import "dotenv/config";
import express from "express";
import swaggerUi from "swagger-ui-express";
import { swaggerSpec } from "./common/swagger";
import { tenantMiddleware } from "./tenant/tenant.middleware";
import { requireAuth } from "./auth/auth.middleware";
import { requireRole, changeUserRole } from "./rbac/rbac.guard";
import { listDocuments, createDocument, getDocumentById } from "./documents/documents.controller";
import { login } from "./auth/auth.service";
import { retryAfterSeconds, registerFailure, registerSuccess } from "./auth/login-rate-limit";
import { logEvent } from "./audit/audit.service";

const app = express();
app.use(express.json());

// Swagger UI
app.use("/api-docs", swaggerUi.serve, swaggerUi.setup(swaggerSpec, {
  customCss: '.swagger-ui .topbar { display: none }',
  customSiteTitle: "TaskFlow API Documentation",
}));

/**
 * @swagger
 * /auth/login:
 *   post:
 *     tags:
 *       - Authentication
 *     summary: Login and get access token
 *     description: Authenticate with email and password to receive JWT tokens
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/LoginRequest'
 *     responses:
 *       200:
 *         description: Login successful
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/LoginResponse'
 *       401:
 *         description: Invalid credentials
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 *       429:
 *         description: Too many failed attempts (5 per account or 20 per IP within 15 minutes)
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Error'
 */
app.post("/auth/login", async (req, res) => {
  const { email, password } = req.body ?? {};
  if (typeof email !== "string" || typeof password !== "string") {
    return res.status(400).json({ error: "INVALID_REQUEST" });
  }
  const ip = req.ip ?? "unknown";
  const emailKey = email;

  // Anti brute force : bloqué AVANT de vérifier le mot de passe.
  const retryAfter = retryAfterSeconds(ip, emailKey);
  if (retryAfter > 0) {
    res.setHeader("Retry-After", String(retryAfter));
    return res.status(429).json({ error: "TOO_MANY_ATTEMPTS" });
  }

  try {
    const tokens = await login(email, password);
    registerSuccess(ip, emailKey);
    res.json(tokens);
  } catch (err) {
    if ((err as Error).message !== "INVALID_CREDENTIALS") {
      // Panne technique (ex. base injoignable) : ne pas la déguiser en mauvais mot de passe.
      console.error("login failed", err);
      return res.status(500).json({ error: "INTERNAL_ERROR" });
    }
    if (registerFailure(ip, emailKey)) {
      await logEvent("auth.login_blocked", null, null, { email: emailKey, ip }).catch((e) =>
        console.error("audit log failed", e)
      );
    }
    res.status(401).json({ error: "INVALID_CREDENTIALS" });
  }
});

// Toutes les routes /api/* nécessitent un JWT valide + un tenant résolu.
app.use("/api", requireAuth, tenantMiddleware);

/**
 * @swagger
 * /api/documents:
 *   get:
 *     tags:
 *       - Documents
 *     summary: List all documents for the current tenant
 *     description: Returns all documents visible to the authenticated user based on RLS policies
 *     security:
 *       - bearerAuth: []
 *       - tenantId: []
 *     responses:
 *       200:
 *         description: List of documents
 *         content:
 *           application/json:
 *             schema:
 *               type: array
 *               items:
 *                 $ref: '#/components/schemas/Document'
 *       401:
 *         description: Not authenticated
 *       400:
 *         description: Missing tenant ID
 */
app.get("/api/documents", listDocuments);

/**
 * @swagger
 * /api/documents:
 *   post:
 *     tags:
 *       - Documents
 *     summary: Create a new document
 *     description: Creates a document in the current tenant
 *     security:
 *       - bearerAuth: []
 *       - tenantId: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/CreateDocumentRequest'
 *     responses:
 *       201:
 *         description: Document created successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 id:
 *                   type: string
 *                   format: uuid
 *       401:
 *         description: Not authenticated
 *       400:
 *         description: Missing tenant ID or invalid request
 */
app.post("/api/documents", createDocument);

/**
 * @swagger
 * /api/documents/{id}:
 *   get:
 *     tags:
 *       - Documents
 *     summary: Get a specific document by ID
 *     description: Returns a document if it belongs to the current tenant (enforced by RLS)
 *     security:
 *       - bearerAuth: []
 *       - tenantId: []
 *     parameters:
 *       - in: path
 *         name: id
 *         required: true
 *         schema:
 *           type: string
 *           format: uuid
 *         description: Document ID
 *     responses:
 *       200:
 *         description: Document details
 *         content:
 *           application/json:
 *             schema:
 *               $ref: '#/components/schemas/Document'
 *       404:
 *         description: Document not found or not accessible
 *       401:
 *         description: Not authenticated
 */
app.get("/api/documents/:id", getDocumentById);

/**
 * @swagger
 * /api/users/change-role:
 *   post:
 *     tags:
 *       - RBAC
 *     summary: Change a user's role
 *     description: Allows OWNER to change roles of users in their tenant (requires priority >= 50)
 *     security:
 *       - bearerAuth: []
 *       - tenantId: []
 *     requestBody:
 *       required: true
 *       content:
 *         application/json:
 *           schema:
 *             $ref: '#/components/schemas/ChangeRoleRequest'
 *     responses:
 *       200:
 *         description: Role changed successfully
 *         content:
 *           application/json:
 *             schema:
 *               type: object
 *               properties:
 *                 ok:
 *                   type: boolean
 *                   example: true
 *       403:
 *         description: Insufficient permissions
 *       401:
 *         description: Not authenticated
 *       400:
 *         description: Unknown role
 */
app.post("/api/users/change-role", requireRole(50), changeUserRole);

// Exportée pour que les tests (supertest) utilisent exactement la même app.
export default app;

// Pas de serveur HTTP sous Jest : supertest appelle l'app directement.
if (process.env.NODE_ENV !== "test") {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, () => {
    console.log(`TaskFlow playground running on :${PORT}`);
    console.log(`📚 Swagger UI available at http://localhost:${PORT}/api-docs`);
  });
}