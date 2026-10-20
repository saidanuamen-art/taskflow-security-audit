import { Pool } from "pg";

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL || "postgres://taskflow_app:taskflow_app_dev_pw@localhost:5432/taskflow",
});
