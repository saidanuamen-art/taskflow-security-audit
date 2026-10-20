# Docker Setup Guide - TaskFlow Playground (Instance 2)

## Overview

This is a fully dockerized TaskFlow instance running alongside your existing TaskFlow project without conflicts.

## Container Details

| Service | Container Name | Host Port | Internal Port |
|---------|---------------|-----------|---------------|
| PostgreSQL | taskflow2_pg | 5433 | 5432 |
| Node.js App | taskflow2_app | 3001 | 3000 |

**Network**: taskflow2_network (isolated bridge network)
**Volume**: taskflow2_pg_data (PostgreSQL data persistence)

## Quick Start

### 1. Start All Services
```bash
npm run docker:up
```

This will:
- Build the Node.js Docker image
- Start PostgreSQL container on port 5433
- Start Node.js app container on port 3001
- Create isolated Docker network

### 2. Initialize Database
```bash
npm run docker:db:init
```

This creates tables, roles, and seeds test data.

### 3. Access the Application
- **API Base URL**: http://localhost:3001
- **Login Endpoint**: POST http://localhost:3001/auth/login

### 4. Test Login
```bash
curl -X POST http://localhost:3001/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "owner@alpha.test",
    "password": "Password123!"
  }'
```

## Test Accounts

| Email | Password | Tenant | Role |
|-------|----------|--------|------|
| owner@alpha.test | Password123! | Tenant Alpha | OWNER |
| member@alpha.test | Password123! | Tenant Alpha | MEMBER |
| owner@beta.test | Password123! | Tenant Beta | OWNER |
| member@beta.test | Password123! | Tenant Beta | MEMBER |

## Useful Commands

### View Logs
```bash
# App logs only
npm run docker:logs

# All services logs
npm run docker:logs:all
```

### Restart App (after code changes that need container restart)
```bash
npm run docker:restart
```

### Rebuild and Restart (after dependency changes)
```bash
npm run docker:rebuild
```

### Stop All Services
```bash
npm run docker:down
```

### Stop and Remove Volumes (complete cleanup)
```bash
docker compose down -v
```

## Running Both Projects Simultaneously

Your original TaskFlow project uses:
- Container: 	askflow_pg
- PostgreSQL Port: 5432
- App Port: 3000 (if running on host)

This dockerized instance uses:
- Containers: 	askflow2_pg, 	askflow2_app
- PostgreSQL Port: 5433
- App Port: 3001

Both can run at the same time without conflicts!

## Hot Reloading

Code changes in src/ directory are automatically detected and the app restarts thanks to:
- Volume mount: ./src:/app/src
- ts-node-dev with --respawn flag

Just edit your code and save - no need to restart containers!

## Troubleshooting

### Port Already in Use
```bash
# Check what's using the port
netstat -ano | findstr :3001
netstat -ano | findstr :5433

# Stop this instance
npm run docker:down
```

### Database Connection Errors
```bash
# Check if PostgreSQL is ready
docker exec taskflow2_pg pg_isready -U taskflow

# View PostgreSQL logs
docker logs taskflow2_pg
```

### App Won't Start
```bash
# Check app logs
docker logs taskflow2_app

# Rebuild image
npm run docker:rebuild
```

### Permission Issues (Windows)
If you see permission errors with volumes, ensure Docker Desktop has access to your drive in Settings > Resources > File Sharing.

## Database Access

### Connect via psql
```bash
docker exec -it taskflow2_pg psql -U taskflow -d taskflow
```

### Backup Database
```bash
docker exec taskflow2_pg pg_dump -U taskflow taskflow > backup.sql
```

### Restore Database
```bash
cat backup.sql | docker exec -i taskflow2_pg psql -U taskflow -d taskflow
```

## Environment Variables

Defined in docker-compose.yml:
- DATABASE_URL: postgres://taskflow:taskflow_dev_pw@taskflow2_pg:5432/taskflow
- PORT: 3000 (internal)
- JWT_SECRET: taskflow-super-secret-key

To override, create a .env file or modify docker-compose.yml.

## Architecture

```
┌─────────────────────────────────────┐
│   Host Machine (Windows)            │
│                                     │
│  ┌──────────────────────────────┐  │
│  │  Docker Network              │  │
│  │  (taskflow2_network)         │  │
│  │                              │  │
│  │  ┌────────────────────────┐  │  │
│  │  │  taskflow2_pg          │  │  │
│  │  │  (PostgreSQL)          │  │  │
│  │  │  Internal: 5432        │  │  │
│  │  └──────────┬─────────────┘  │  │
│  │             │                │  │
│  │  ┌──────────▼─────────────┐  │  │
│  │  │  taskflow2_app         │  │  │
│  │  │  (Node.js + Express)   │  │  │
│  │  │  Internal: 3000        │  │  │
│  │  └────────────────────────┘  │  │
│  │                              │  │
│  └──────────────────────────────┘  │
│         │              │            │
│    Port 5433      Port 3001         │
│         │              │            │
└─────────┼──────────────┼────────────┘
          │              │
     [PostgreSQL]    [HTTP API]
     Client Tools   Browser/Postman
```

## Development Workflow

1. Make code changes in src/
2. App automatically restarts (hot reload)
3. Test via http://localhost:3001
4. Check logs: 
pm run docker:logs
5. Commit changes to Git

## Production Considerations

This setup is for **development only**. For production:
- Use multi-stage Docker build
- Don't use ts-node-dev (compile TypeScript first)
- Use production-grade secrets management
- Add health checks
- Use proper logging drivers
- Implement rate limiting
- Add HTTPS/TLS
- Use environment-specific configs

---

**Need help?** Check logs with 
pm run docker:logs:all or review the main README.md for project context.
