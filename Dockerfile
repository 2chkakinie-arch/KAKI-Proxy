# Generic Docker image — works on Fly.io / Koyeb / DigitalOcean App Platform / etc.
FROM node:20-alpine
WORKDIR /app
COPY package.json ./
COPY index.js     ./
COPY api          ./api
ENV PORT=8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
  CMD wget -qO- http://127.0.0.1:8080/health || exit 1
CMD ["node", "index.js"]
