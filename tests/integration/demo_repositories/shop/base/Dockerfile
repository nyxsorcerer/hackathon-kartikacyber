FROM node:20.11.1-alpine
WORKDIR /app
COPY . .
RUN npm ci --omit=dev
ENV PORT=8080
EXPOSE 8080
USER node
CMD ["node", "server.js"]
