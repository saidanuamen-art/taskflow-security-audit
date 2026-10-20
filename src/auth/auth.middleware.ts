import { Request, Response, NextFunction } from "express";
import { verifyAccessToken } from "./auth.service";

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  const header = req.headers["authorization"];
  if (!header || !header.startsWith("Bearer ")) {
    return res.status(401).json({ error: "MISSING_TOKEN" });
  }

  try {
    const payload = verifyAccessToken(header.replace("Bearer ", ""));
    (req as any).user = payload;
    next();
  } catch {
    return res.status(401).json({ error: "INVALID_TOKEN" });
  }
}
