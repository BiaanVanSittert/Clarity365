FROM node:20-alpine AS base

WORKDIR /app

# better-sqlite3 is a native module. Alpine (musl libc) doesn't always have a
# matching prebuilt binary, so make sure the toolchain is here for npm to
# compile it from source as a fallback.
RUN apk add --no-cache python3 make g++

COPY package*.json ./
RUN npm ci

COPY . .
RUN npm run build

EXPOSE 3000

ENV NODE_ENV=production
ENV HOST=127.0.0.1
ENV PORT=3000

CMD ["npm", "start"]
