FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN if [ -f package.json ]; then npm install; fi

COPY . .

EXPOSE 3000

CMD ["node", "server.js"]
