FROM node:20-alpine AS build
WORKDIR /app/backend
COPY backend/package*.json ./
RUN npm install
COPY backend/ ./
RUN echo "DATABASE_URL=postgresql://dummy:dummy@localhost/dummy" > .env && \
    npm run prisma:generate && \
    npm run build

FROM node:20-alpine AS runtime
WORKDIR /app/backend
ENV NODE_ENV=production
COPY --from=build /app/backend/package*.json ./
RUN npm install --omit=dev
COPY --from=build /app/backend/dist ./dist
COPY --from=build /app/backend/prisma ./prisma
EXPOSE 5000
CMD ["node", "dist/main.js"]
