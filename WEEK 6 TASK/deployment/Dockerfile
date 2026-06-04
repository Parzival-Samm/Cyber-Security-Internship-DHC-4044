# Step 1: Use an explicit, lightweight, verified LTS Node image
FROM node:20-alpine AS base

# Step 2: Set the working directory inside the container
WORKDIR /usr/src/app

# Step 3: Copy package files first to leverage Docker layer caching
COPY package*.json ./

# Step 4: Install ONLY production dependencies (ignores devDependencies)
# 'npm ci' ensures clean, deterministic builds based exactly on your lockfile
RUN npm ci --only=production

# Step 5: Copy the rest of the application source code
COPY . .

# Step 6: Security Hardening - Enforce Least Privilege Principle
# Default Node images come with a built-in unprivileged user named 'node'.
# Running as 'node' instead of 'root' stops container breakout exploits.
RUN chown -R node:node /usr/src/app
USER node

# Step 7: Expose the application port
EXPOSE 3000

# Step 8: Set production environment variables
ENV NODE_ENV=production

# Step 9: Define runtime command
CMD ["node", "index.js"]