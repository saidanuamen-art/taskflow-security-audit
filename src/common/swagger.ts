import swaggerJsdoc from "swagger-jsdoc";

const options: swaggerJsdoc.Options = {
  definition: {
    openapi: "3.0.0",
    info: {
      title: "TaskFlow API - Multi-Tenant SaaS",
      version: "1.0.0",
      description: `
TaskFlow is a multi-tenant SaaS application for task and document management.

## ⚠️ Educational Purpose
This is a deliberately vulnerable playground environment for security training.

## Authentication
Most endpoints require:
- **Bearer Token**: Obtain via /auth/login
- **x-tenant-id Header**: UUID of the tenant

## Test Accounts
All passwords: \`Password123!\`

| Email | Tenant | Role |
|-------|--------|------|
| owner@alpha.test | Alpha (11111111-1111-1111-1111-111111111111) | OWNER |
| member@alpha.test | Alpha | MEMBER |
| owner@beta.test | Beta (22222222-2222-2222-2222-222222222222) | OWNER |
| member@beta.test | Beta | MEMBER |
      `,
      contact: {
        name: "TaskFlow Playground",
      },
    },
    servers: [
      {
        url: "http://localhost:3001",
        description: "Development server (Docker instance)",
      },
      {
        url: "http://localhost:3000",
        description: "Development server (Original instance)",
      },
    ],
    components: {
      securitySchemes: {
        bearerAuth: {
          type: "http",
          scheme: "bearer",
          bearerFormat: "JWT",
          description: "Enter your JWT token obtained from /auth/login",
        },
        tenantId: {
          type: "apiKey",
          in: "header",
          name: "x-tenant-id",
          description: "UUID of the tenant (11111111-1111-1111-1111-111111111111 for Alpha, 22222222-2222-2222-2222-222222222222 for Beta)",
        },
      },
      schemas: {
        LoginRequest: {
          type: "object",
          required: ["email", "password"],
          properties: {
            email: {
              type: "string",
              format: "email",
              example: "owner@alpha.test",
            },
            password: {
              type: "string",
              format: "password",
              example: "Password123!",
            },
          },
        },
        LoginResponse: {
          type: "object",
          properties: {
            accessToken: {
              type: "string",
              description: "JWT access token (valid for 15 minutes)",
            },
            refreshToken: {
              type: "string",
              description: "JWT refresh token (valid for 7 days)",
            },
          },
        },
        Document: {
          type: "object",
          properties: {
            id: {
              type: "string",
              format: "uuid",
            },
            tenant_id: {
              type: "string",
              format: "uuid",
            },
            owner_id: {
              type: "string",
              format: "uuid",
            },
            title: {
              type: "string",
            },
            content: {
              type: "string",
            },
            created_at: {
              type: "string",
              format: "date-time",
            },
          },
        },
        CreateDocumentRequest: {
          type: "object",
          required: ["title", "content"],
          properties: {
            title: {
              type: "string",
              example: "My Document",
            },
            content: {
              type: "string",
              example: "This is the document content",
            },
          },
        },
        ChangeRoleRequest: {
          type: "object",
          required: ["targetUserId", "newRoleName"],
          properties: {
            targetUserId: {
              type: "string",
              format: "uuid",
              example: "77f5ce62-6117-4735-8a68-4f0441738275",
            },
            newRoleName: {
              type: "string",
              enum: ["OWNER", "MEMBER", "GUEST"],
              example: "MEMBER",
            },
          },
        },
        Error: {
          type: "object",
          properties: {
            error: {
              type: "string",
            },
          },
        },
      },
    },
    tags: [
      {
        name: "Authentication",
        description: "User authentication endpoints",
      },
      {
        name: "Documents",
        description: "Document management endpoints (requires auth + tenant)",
      },
      {
        name: "RBAC",
        description: "Role-Based Access Control endpoints (requires OWNER role)",
      },
    ],
  },
  apis: ["./src/**/*.ts"],
};

export const swaggerSpec = swaggerJsdoc(options);