FROM node:22.21.1-bookworm-slim
ENV NODE_ENV=production
WORKDIR /opt/signal-tus
COPY package.json ./
RUN npm install --omit=dev --no-audit --no-fund
COPY src ./src
RUN mkdir -p /var/lib/signal-tus && chown -R node:node /opt/signal-tus /var/lib/signal-tus
USER node
EXPOSE 8096
CMD ["node", "src/server.js"]
