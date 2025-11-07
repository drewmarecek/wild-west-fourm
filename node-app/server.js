const express = require('express');
const cors = require('cors');
const session = require('express-session');
const userRoutes = require('./routes/users');
const commentRoutes = require('./routes/comments');

const app = express();
const PORT = process.env.PORT || 3000;

//middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
  session({
    secret: 'not-secret',
    resave: false,
    saveUninitialized: true,
    cookie: {}
  })
);

//in-memory storage
app.locals.users = [];
app.locals.comments = [];

//routes
app.use('/api/users', userRoutes);
app.use('/api/comments', commentRoutes);

//root endpoint
app.get('/', (req, res) => {
  res.json({
    message: 'Wild West Forum API',
    version: '1.0.0',
    endpoints: {
      users: '/api/users',
      comments: '/api/comments'
    }
  });
});

//404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    error: 'Endpoint not found',
    message: `The endpoint ${req.method} ${req.originalUrl} does not exist`
  });
});

//error handler
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    error: 'Internal server error',
    message: 'Something went wrong on the server'
  });
});

app.listen(PORT, () => {
  console.log(`Wild West Forum running on http://localhost:${PORT}`);
});
