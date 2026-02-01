FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm ci --only=production

COPY dist ./dist

ENV PORT=3001
EXPOSE 3001

CMD ["node", "dist/server.js"]
