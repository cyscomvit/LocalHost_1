FROM node:16-alpine

WORKDIR /app

COPY package.json .
RUN npm config set fetch-timeout 300000 && \
    npm config set fetch-retries 5 && \
    npm config set fetch-retry-mintimeout 20000 && \
    npm config set fetch-retry-maxtimeout 120000 && \
    npm install

COPY . .

EXPOSE 3000

# INTENTIONALLY INSECURE: Running in development mode
# TODO: Build for production, serve with nginx
CMD ["npm", "start"]
