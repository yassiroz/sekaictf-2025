# Use official Node.js runtime as base image
FROM node:18-alpine

# Set working directory in container
WORKDIR /app

# Create a non-root user for security
RUN addgroup -g 1001 -S nodejs && \
    adduser -S nextjs -u 1001

# Copy package files
COPY package*.json ./

# Install dependencies
# Use npm install since we don't have package-lock.json
RUN npm install --omit=dev && npm cache clean --force

# Copy source code
COPY src/ ./src/

# Create logs directory and set permissions
RUN mkdir -p logs && \
    chown -R nextjs:nodejs /app

# Switch to non-root user
USER nextjs

# Expose port
EXPOSE 3000

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD node -e "const http = require('http'); \
    const options = { host: 'localhost', port: 3000, path: '/api/health', timeout: 2000 }; \
    const req = http.request(options, (res) => process.exit(res.statusCode === 200 ? 0 : 1)); \
    req.on('error', () => process.exit(1)); \
    req.end();"

# Start the application
CMD ["node", "src/server.js"]
