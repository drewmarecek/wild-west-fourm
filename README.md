Drew Marecek
11/13/25
COS 498
Midterm

Overview:
This is a minimal, insecure web fourm that allows users to create accounts, log in via a session cookie and post comments. Users are able to create an account with a password, log in and post comments. The styling and html was done with the help of AI.

Requirements:
Node.js 18+
Docker and Docker Compose
Git

How to run:
Put the following commands in your terminal to get on the forum:

git clone git@github.com:USERNAME/wild-west-fourm.git
cd wild-west-forum
docker compose down
docker compose build
docker compose up -d

Then, in a web browser, go to: http://104.131.168.242:7823

Bugs:
No known errors.
