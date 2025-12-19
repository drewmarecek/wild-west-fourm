Drew Marecek
12/19/2025
COS 498
Final Project

Overview:
This secure web fourm that builds on the "Wild West Fourm" midterm. It includes databse persistence, security features, user profiles, password recovery, real-time chat functionality and enhanced comment features. 
It uses SQLite3 for data persistence, implementes secure password hashing, account lockout and HTTPS. It provides user profile management, includes a real time chat system using Socket.io and implements pagination for comment history. 

Features:
- Authenticaion/Security
User registration and login
Secure password hashing and Argon2
Password strength enforcement
Login attempt logging
Account lockout after repeated failed login attempts
Session based authenticaiton with cookies

- User Profiles
Public display names
Editable profile information
Customizable display name color stored in the database
Profile page showing user comment history

- Comment System
Create, edit and delete comments
Supports bold, itilics, links and code blocks
Timestamp updates when commnets are edited
Pagination with total comment count
"Read more" for long comments
Ability to edit/delete your own comments

- Live Chat
Real time chat using Socket.IO
Chat message persistence
Username color displayed consistently with user profile
Authentication needed for chat access

- Infastructure
SQLite database
PM2 process manager
Nginx reverse proxy
HTTPS via Let's Encrypt
Deployed on Ubuntu Linux

Tech Stack:
Backend: Node.js, Express
Database: SQLite
Authentication: express-session, Argon2
Real-time: Socket.IO
Templating: Handlebars
Markdown: marked
Process Manager: PM2
Web Server: Nginx
TLS/SSL: Let's Encrypt

API Endpoints:
-Authenticaiton
POST /register - create a new user account
POST /login - Authenticate user and create new session
POST /logout - Destroy user session
POST /forgot-password - Generate password reset token
POST /reset-password - Reset password using token

-Profile Management
GET /profile - View user profile
POST /profile/password - change password
POST /profile/email - update email address
POST /profile/display-name - Update display name
POST /profile/color - update display name color

-Comments
GET /commnets - view paginated comments
POST /comment - Create a comment
GET /comment/:id/edit - edit comment form
POST /comment/:id/edit - update comment
POST /comment/:id/delete - delete comment
GET /user/:id/comments - view user's comment history

-Chat
GET /chat - live chat interface
POST /api/chat/message - send chat message
GET /api/chat/history - retrieve chat messages

Requirements:
Node.js 18+
npm
SQLite3
Linux server
PM2
Nginx
Certbot

How to run locally:
Put the following commands in your terminal to get on the forum:

git clone git@github.com:drewmarecek/wild-west-fourm.git
cd wild-west-forum/node-app
npm install
mkdir -p data
node server.js
Then visit: http://localhost:3000

How to deploy:
Run the folloiwng commands on the server:

git clone git@github.com:drewmarecek/wild-west-fourm.git
cd wild-west-forum/node-app
npm install
mkdir -p data
pm2 start server.js --name wildwest
pm2 save
sudo certbot --nginx -d assignment3solutions.com -d www.assignment3solutions.com

Security Notes:
Passwords are hashed using Argon2
Server side sessions mitigate the risk of session hijacking
Login attempts are logged and accounts are temporarily locked after repeated failures.

Environment Variables:
PORT - Port for Express server
SESSION_SECRET - Secret used to sign session cookies
NODE_ENV - Application environment

Trade offs:
In the comment section, I decided to implement the "see more" option, the ability to delete/edit comments and the ability to use bold, italics or code blocks in user comments as I thought those would be the msot meaningful if they were added. 
Being able to reset a users password through email verification wasn't completed as it was taking too much of my time. It was working on localhost where it would send a verification link in the terminal and the user would be able to reset from there but I knew it would take too long to implement on the server so I omited it.

Known limitation or issues:
When trying to send a user a reset password link, the email doesn't get sent to the user. 