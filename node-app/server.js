const express = require('express');
const session = require('express-session');
const bodyParser = require('body-parser');
const exphbs = require('express-handlebars');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

//in memory state
const users = [];
const comments = [];

//view engine
app.engine('hbs', exphbs.engine({ extname: '.hbs' }));
app.set('view engine', 'hbs');
app.set('views', path.join(__dirname, 'views'));

//middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(express.static(path.join(__dirname, 'public')));
app.use(session({ secret: 'not-secret', resave: false, saveUninitialized: true }));
app.use((req, res, next) => {res.locals.user = req.session.user; 
next();});

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
app.post('/login', (req, res) => {
  const user = users.find(u => u.username === req.body.username && u.password === req.body.password);
  if (!user) return res.render('login', { error: 'Invalid credentials' });
  req.session.user = user.username;
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
