# Use Node.js 20 Alpine for smaller image size
FROM node:20-alpine

# Set working directory
WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm ci

# Copy source code and TypeScript config
COPY tsconfig.json ./
COPY src ./src

# Expose port 3000 (internal container port)
EXPOSE 3000

# Start development server with hot-reloading
CMD ["npm", "run", "dev"]
