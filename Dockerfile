FROM node:22-alpine

WORKDIR /app

COPY package.json server.json LICENSE NOTICE README.md ./
COPY bin ./bin
COPY src ./src

ENTRYPOINT ["node", "/app/bin/mcp-server.mjs"]
