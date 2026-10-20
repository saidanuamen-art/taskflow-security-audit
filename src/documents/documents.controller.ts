import { Request, Response } from "express";

export async function listDocuments(req: Request, res: Response) {
  const client = (req as any).dbClient;
  const user = (req as any).user;
  
  // VULN-05 FIX: Defense-in-depth - filtre applicatif par tenant_id
  const result = await client.query(
    `SELECT id, title, content, created_at FROM documents WHERE tenant_id = $1`,
    [user.tenantId]
  );
  res.json(result.rows);
}

export async function createDocument(req: Request, res: Response) {
  const client = (req as any).dbClient;
  const user = (req as any).user;
  const { title, content } = req.body;

  const result = await client.query(
    `INSERT INTO documents (tenant_id, owner_id, title, content)
     VALUES ($1, $2, $3, $4) RETURNING id`,
    [user.tenantId, user.sub, title, content]
  );

  res.status(201).json({ id: result.rows[0].id });
}

export async function getDocumentById(req: Request, res: Response) {
  const client = (req as any).dbClient;
  const user = (req as any).user;
  const { id } = req.params;

  // VULN-05 FIX: Defense-in-depth - filtre applicatif en plus de RLS
  const result = await client.query(
    `SELECT * FROM documents WHERE id = $1 AND tenant_id = $2`,
    [id, user.tenantId]
  );

  if (result.rows.length === 0) return res.status(404).json({ error: "NOT_FOUND" });
  res.json(result.rows[0]);
}
