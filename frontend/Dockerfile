FROM node:18-slim AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
ARG REACT_APP_API_URL
ARG REACT_APP_MAILPIT_URL
ENV REACT_APP_API_URL=$REACT_APP_API_URL
ENV REACT_APP_MAILPIT_URL=$REACT_APP_MAILPIT_URL
RUN npm run build

FROM node:18-slim
WORKDIR /app
RUN npm install -g serve
COPY --from=builder /app/build ./build
EXPOSE 3000
CMD ["serve", "-s", "build", "-l", "3000"]