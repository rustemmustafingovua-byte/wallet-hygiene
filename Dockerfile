FROM node:22-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY --chown=node:node bin bin
COPY --chown=node:node src src
COPY --chown=node:node package.json README.md LICENSE ./
COPY --chown=node:node docs/SECURITY.md docs/SECURITY.md
ENV HOST=0.0.0.0
ENV PORT=8787
ENV X402_ENABLED=false
EXPOSE 8787
USER node
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD node -e "fetch('http://127.0.0.1:'+(process.env.PORT||8787)+'/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"
CMD ["node", "bin/wallet-hygiene.js", "serve"]
