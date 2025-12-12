const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const exphbs = require('express-handlebars');
const path = require('path');
const argon2 = require('argon2');
const Database = require('better-sqlite3');

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000;

const app = express();
const PORT = process.env.PORT || 3000;

const db = new Database(path.join(__dirname, 'data', 'app.db'));
db.pragma('foreign_keys = ON');

//view engine
app.engine('hbs', exphbs.engine({ extname: '.hbs' }));
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));

//middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({ secret: 'not-secret', resave: false, saveUninitialized: false }));
app.use((req, res, next) => {res.locals.user = req.session.user; 
next();});

//helper function to ensure every login attempt is loggged
function logLoginAttempt(db, { username, ip, success }) {
  db.prepare(`
    INSERT INTO login_attempts (username, ip, attempted_at, success)
    VALUES (?, ?, ?, ?)
  `).run(
    username,
    ip,
    Date.now(),
    success ? 1 : 0
  );
}

//routes
app.get('/', (req, res) => res.render('home'));
app.get('/register', (req, res) => res.render('register'));
app.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password || users.find(u => u.username === username))
    return res.render('register', { error: 'Invalid or taken username' });
  users.push({ username, password });
  res.redirect('/login');
});
app.get('/login', (req, res) => res.render('login'));
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  const ip = req.ip;
  const now = Date.now();

  const user = db.prepare(`
    SELECT * FROM users WHERE username = ?
  `).get(username);

  //account lockout check
  if (user && user.lockout_until && user.lockout_until > now) {
    logLoginAttempt(db, { username, ip, success: false });

    const unlockTime = new Date(user.lockout_until).toLocaleTimeString();
    return res.render('login', {
      error: `Account locked until ${unlockTime}`
    });
  }

  //invalid user or wrong password
  if (!user || !(await argon2.verify(user.password_hash, password))) {

    if (user) {
      const failedCount = user.failed_login_count + 1;
      const lockoutUntil =
        failedCount >= MAX_FAILED_ATTEMPTS
          ? now + LOCKOUT_DURATION
          : null;

      db.prepare(`
        UPDATE users
        SET failed_login_count = ?, lockout_until = ?
        WHERE id = ?
      `).run(failedCount, lockoutUntil, user.id);
    }

    logLoginAttempt(db, { username, ip, success: false });

    return res.render('login', {
      error: 'Invalid username or password'
    });
  }

  //successful login
  db.prepare(`
    UPDATE users
    SET failed_login_count = 0,
        lockout_until = NULL
    WHERE id = ?
  `).run(user.id);

  logLoginAttempt(db, { username, ip, success: true });

  req.session.user = {
    id: user.id,
    username: user.username,
    displayName: user.display_name
  };

  res.redirect('/comments');
});

app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));
app.get('/comments', (req, res) => res.render('comments', { comments, user: req.session.user }));
app.get('/comment/new', (req, res) => {
  if (!req.session.user) return res.render('login', { error: 'Please log in first' });
  res.render('new-comment');
});
app.post('/comment', (req, res) => {
  if (!req.session.user) return res.render('login', { error: 'Please log in' });
  if (!req.body.text?.trim()) return res.render('new-comment', { error: 'Comment cannot be empty' });
  comments.push({ author: req.session.user, text: req.body.text, createdAt: new Date() });
  res.redirect('/comments');
});

//start server on PORT
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
