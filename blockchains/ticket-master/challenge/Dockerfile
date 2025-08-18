FROM node:22-alpine

WORKDIR /app

COPY package.json yarn.lock ./

RUN yarn install

COPY . .
RUN chmod +x /app/entrypoint.sh

EXPOSE 3000

CMD ["/app/entrypoint.sh"]
