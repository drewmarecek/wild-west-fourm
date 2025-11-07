FROM node:18-alpine

#set working directory
WORKDIR /usr/src/app

#copy package files
COPY package.json package-lock.json* ./

#install dependencies
RUN npm install --production

#copy source code
COPY . .

#expose port
EXPOSE 3000

#start the application
CMD ["node", "server.js"]

