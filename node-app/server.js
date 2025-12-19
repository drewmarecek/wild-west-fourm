const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const exphbs = require('express-handlebars');
const path = require('path');
const Database = require('better-sqlite3');
const http = require('http');
const { Server } = require('socket.io');
const marked = require('marked');

marked.setOptions({
  mangle: false,
  headerIds: false
});

const {
  validatePasswordStrength,
  hashPassword,
  verifyPassword
} = require('./security/password');

const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000;
const crypto = require('crypto');
const { timeStamp } = require('console');

const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database(path.join(__dirname, 'data', 'app.db'));
db.pragma('foreign_keys = ON');
const server = http.createServer(app);
const io = new Server(server);

//view engine
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));
app.engine('hbs', exphbs.engine({
  extname: '.hbs',
  helpers: {
  eq: (a, b) => a === b,
  increment: v => v + 1,
  decrement: v => v - 1,
  strlen: s => s.length,
  gt: (a, b) => a > b,
  substring: (s, a, b) => {
    if (typeof s !== 'string') return '';
    return s.substring(a, b);
  },
  formatDate: ts => new Date(ts).toLocaleString()
  }
}));

//middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
const sessionMiddleware = session({
  secret: 'not-secret',
  resave: false,
  saveUninitialized: false
});
app.use(sessionMiddleware);
app.use((req, res, next) => {
  res.locals.user = req.session.user;
  res.locals.displayName = req.session.user?.displayName || null;
  next();
});

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.render('login', { error: "Please log in first" });
  }
  next();
}

function renderProfile(req, res, extra = {}) {
  const user = db.prepare(`
    SELECT username, email, display_name, name_color
    FROM users
    WHERE id = ?
  `).get(req.session.user.id);

  return res.render('profile', { user, ...extra });
}

function generateResetToken() {
  return crypto.randomBytes(32).toString('hex');
}

function hashResetToken(token) {
  return crypto.createHash('sha256').update(token).digest('hex');
}

//login attempt
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

app.get('/profile', requireLogin, (req, res) => {
  renderProfile(req, res);
});

app.get('/forgot-password', (req, res) => {
  res.render('forgot-password');
});

app.get('/reset-password', (req, res) => {
  const { token } = req.query;

  if (!token) {
    return res.render('login', { error: "Invalid reset link" });
  }

  const tokenHash = hashResetToken(token);

  const user = db.prepare(`
    SELECT * FROM users
    WHERE reset_token_hash = ?
      AND reset_token_expires_at > ?
  `).get(tokenHash, Date.now());

  if (!user) {
    return res.render('login', { error: "Reset link expired or invalid" });
  }

  res.render('reset-password', { token });
});

app.post('/profile/password', requireLogin, async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return renderProfile(req, res, { error: "All password fields required" });
  }

  const user = db.prepare(`SELECT * FROM users WHERE id = ?`).get(req.session.user.id);

  const valid = await verifyPassword(user.password_hash, currentPassword);
  if (!valid) {
    return renderProfile(req, res, { error: "Current password incorrect" });
  }

  const pwError = validatePasswordStrength(newPassword);
  if (pwError) {
    return renderProfile(req, res, { error: pwError });
  }

  const newHash = await hashPassword(newPassword);

  db.prepare(`
    UPDATE users
    SET password_hash = ?, updated_at = ?
    WHERE id = ?
  `).run(newHash, Date.now(), user.id);

  req.session.destroy(() => res.redirect('/login'));
});

app.post('/profile/color', requireLogin, (req, res) => {
  const color = req.body.color;

  db.prepare(`
    UPDATE users
    SET name_color = ?
    WHERE id = ?
  `).run(color, req.session.user.id);

  req.session.user.name_color = color;
  res.redirect('/profile');
});

app.post('/register', async (req, res) => {
  const { username, email, displayName, password } = req.body;

  if (!username || !email || !displayName || !password) {
    return res.render('register', { error: "All fields are required" });
  }

  if (username === displayName) {
    return res.render('register', {
      error: "Display name must be different from username"
    });
  }

  const pwError = validatePasswordStrength(password);
  if (pwError) {
    return res.render('register', { error: pwError });
  }

  const existing = db.prepare(`
    SELECT 1 FROM users
    WHERE username = ? OR email = ? OR display_name = ?
  `).get(username, email, displayName);

  if (existing) {
    return res.render('register', {
      error: "Username, email, or display name already taken"
    });
  }

  const passwordHash = await hashPassword(password);

  db.prepare(`
    INSERT INTO users (
      username,
      email,
      display_name,
      password_hash,
      failed_login_count,
      lockout_until,
      created_at,
      updated_at
    )
    VALUES (?, ?, ?, ?, 0, NULL, ?, ?)
  `).run(
    username,
    email,
    displayName,
    passwordHash,
    Date.now(),
    Date.now()
  );

  res.redirect('/login');
});

app.post('/profile/email', requireLogin, async (req, res) => {
  const { email, currentPassword } = req.body;

  if (!email || !currentPassword) {
    return renderProfile(req, res, { error: "Email and password required" });
  }

  const user = db.prepare(`
    SELECT id, password_hash
    FROM users 
    WHERE id = ?
  `).get(req.session.user.id);

  if (!user || !user.password_hash) {
    return renderProfile(req, res, {
      error: "Session error. Please log in again."
    });
  }
  const valid = await verifyPassword(user.password_hash, currentPassword);

  if (!valid) {
    return renderProfile(req, res, { error: "Current password incorrect" });
  }

  const taken = db.prepare(`SELECT 1 FROM users WHERE email = ? AND id != ?`).get(email, user.id);
  if (taken) {
    return renderProfile(req, res, { error: "Email already in use" });
  }

  db.prepare(`
    UPDATE users
    SET email = ?, updated_at = ?
    WHERE id = ?
  `).run(email, Date.now(), user.id);

  return res.redirect('/profile');
});

app.post('/profile/display-name', requireLogin, (req, res) => {
  const { displayName } = req.body;

  if (!displayName) {
    return renderProfile(req, res, { error: "Display name required" });
  }

  if (displayName === req.session.user.username) {
    return renderProfile(req, res, { error: "Display name must differ from username" });
  }

  const taken = db.prepare(`
    SELECT 1 FROM users WHERE display_name = ? AND id != ?
  `).get(displayName, req.session.user.id);

  if (taken) {
    return renderProfile(req, res, { error: "Display name already taken" });
  }

  db.prepare(`
    UPDATE users
    SET display_name = ?, updated_at = ?
    WHERE id = ?
  `).run(displayName, Date.now(), req.session.user.id);

  try {
    db.prepare(`
      UPDATE comments
      SET display_name = ?
      WHERE user_id = ?
    `).run(displayName, req.session.user.id);
  } catch (e) {
  }

  req.session.user.displayName = displayName;

  res.redirect('/profile');
});

app.post('/forgot-password', (req, res) => {
  const { email } = req.body;

  if (!email) {
    return res.render('forgot-password', { error: "Email required" });
  }

  const user = db.prepare(`
    SELECT * FROM users WHERE email = ?
  `).get(email);

  if (!user) {
    return res.render('forgot-password', {
      message: "A reset link has been sent."
    });
  }

  const token = generateResetToken();
  const tokenHash = hashResetToken(token);
  const expiresAt = Date.now() + (30 * 60 * 1000);

  db.prepare(`
    UPDATE users
    SET reset_token_hash = ?, reset_token_expires_at = ?
    WHERE id = ?
  `).run(tokenHash, expiresAt, user.id);

  console.log("\n================PASSWORD RESET LINK================");
  console.log(`http://localhost:3000/reset-password?token=${token}`);

  res.render('forgot-password', {
    message: "A reset link has been sent."
  });
});

app.post('/reset-password', async (req, res) => {
  const { token, password } = req.body;

  if (!token || !password) {
    return res.render('login', { error: "Invalid request" });
  }

  const pwError = validatePasswordStrength(password);
  if (pwError) {
    return res.render('reset-password', { error: pwError, token });
  }

  const tokenHash = hashResetToken(token);

  const user = db.prepare(`
    SELECT * FROM users
    WHERE reset_token_hash = ?
      AND reset_token_expires_at > ?
  `).get(tokenHash, Date.now());

  if (!user) {
    return res.render('login', { error: "Reset link expired or invalid" });
  }

  const newHash = await hashPassword(password);

  db.prepare(`
    UPDATE users
    SET password_hash = ?,
        reset_token_hash = NULL,
        reset_token_expires_at = NULL,
        updated_at = ?
    WHERE id = ?
  `).run(newHash, Date.now(), user.id);

  res.render('login', {
    message: "Password reset successful. Please log in with your new password."
  });
});

app.post('/api/chat/message', requireLogin, (req, res) => {
  const { message } = req.body;

  if (!message || !message.trim()) {
    return res.status(400).json({ error: "Message required" });
  }

  const chatMessage = {
    user_id: req.session.user.id,
    display_name: req.session.user.displayName,
    name_color: req.session.user.name_color,
    message: message.trim(),
    created_at: Date.now()
  };

  const result = db.prepare(`
    INSERT INTO chat_messages (user_id, display_name, name_color, message, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(
    chatMessage.user_id,
    chatMessage.display_name,
    chatMessage.name_color,
    chatMessage.message,
    chatMessage.created_at
  );

  chatMessage.id = result.lastInsertRowid;

  io.emit("chat:new", chatMessage);

  res.json({ success: true });
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
  if (!user || !(await verifyPassword(user.password_hash, password))) {

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
    displayName: user.display_name,
    name_color: user.name_color
  };

  res.redirect('/comments');
});

app.get('/chat', requireLogin, (req, res) => {
  res.render('chat');
});

app.get('/user/:id/comments', (req, res) => {
  const comments = db.prepare(`
    SELECT *
    FROM comments
    WHERE user_id = ?
      AND deleted_at IS NULL
    ORDER BY created_at DESC
  `).all(req.params.id);

  res.render('user-comments', { comments });
});

//io routes
io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});

io.use((socket, next) => {
  if (!socket.request.session?.user) {
    return next(new Error("Not authenticated"));
  }
  next();
});

io.on("connection", (socket) => {
  console.log("SOCKET CONNECTED:", socket.request.session.user.displayName);
});


app.get('/api/chat/history', requireLogin, (req, res) => {
  const messages = db.prepare(`
    SELECT id, display_name, name_color, message, created_at
    FROM chat_messages
    ORDER BY created_at DESC
    LIMIT 50
  `).all();

  res.json(messages.reverse());
});

app.post('/logout', (req, res) => req.session.destroy(() => res.redirect('/')));

app.get('/comments', (req, res) => {
  const pageSize = 10;
  const page = Math.max(parseInt(req.query.page) || 1, 1);
  const offset = (page - 1) * pageSize;

  const total = db.prepare(`
    SELECT COUNT(*) AS count
    FROM comments
    WHERE deleted_at IS NULL
  `).get().count;

  const comments = db.prepare(`
    SELECT 
      comments.*,
      users.name_color
    FROM comments
    JOIN users ON users.id = comments.user_id
    WHERE comments.deleted_at IS NULL
    ORDER BY comments.created_at DESC
    LIMIT ? OFFSET ?
  `).all(pageSize, offset);

  const totalPages = Math.ceil(total / pageSize);

  res.render('comments', {
    comments,
    total,
    page,
    totalPages,
    hasPrev: page > 1,
    hasNext: page < totalPages
  });
});

app.get('/comment/new', (req, res) => {
  if (!req.session.user) return res.render('login', { error: 'Please log in first' });
  res.render('new-comment');
});

app.get('/comment/:id/edit', requireLogin, (req, res) => {
  const comment = db.prepare(`
    SELECT *
    FROM comments
    WHERE id = ? AND user_id = ? AND deleted_at IS NULL
  `).get(req.params.id, req.session.user.id);

  if (!comment) return res.redirect('/comments');

  res.render('edit-comment', { comment });
});

app.post('/comment', requireLogin, (req, res) => {
  const rawText = req.body.text?.trim();

  if (!rawText) {
    return res.render('new-comment', { error: "Comment cannot be empty" });
  }

  if (rawText.length > 2000) {
    return res.render('new-comment', { error: "Comment too long" });
  }

  const html = marked.parse(rawText);

  db.prepare(`
    INSERT INTO comments (user_id, display_name, text, html, created_at)
    VALUES (?, ?, ?, ?, ?)
  `).run(
    req.session.user.id,
    req.session.user.displayName,
    rawText,
    html,
    Date.now()
  );

  res.redirect('/comments');
});

app.post('/comment/:id/delete', requireLogin, (req, res) => {
  db.prepare(`
    UPDATE comments
    SET deleted_at = ?
    WHERE id = ? AND user_id = ?
  `).run(
    Date.now(),
    req.params.id,
    req.session.user.id
  );

  res.redirect('/comments');
});

//edit comment
  app.post('/comment/:id/edit', requireLogin, (req, res) => {
    const rawText = req.body.text?.trim();
    if (!rawText || rawText.length > 2000) {
      return res.redirect('/comments');
    }

    const html = marked.parse(rawText);

  db.prepare(`
    UPDATE comments
    SET text = ?, html = ?, updated_at = ?
    WHERE id = ? AND user_id = ?
  `).run(
    rawText,
    html,
    Date.now(),
    req.params.id,
    req.session.user.id
  );

    res.redirect('/comments');
});

//start server
server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});