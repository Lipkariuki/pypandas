const express = require('express');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const router = require('./routes/routes');
const globalErrorHandler = require('./controllers/errorController');
const app = express();

app.use(cookieParser());
app.use(express.json()); // JSON parse

/**
 * morgan logger as a 3rd party middleware
 */
if (process.env.NODE_ENV === 'development') {
  app.use(morgan('dev')); // logging only while
}

/**
 * custom middle ware
 */
app.use((req, res, next) => {
  req.requestTime = new Date().toISOString();
  next(); // to continue the req res cycle
});

/**
 * custom router middleware
 */
app.use('/api/v1', router);

app.all('*', (req, res, next) => {
  next(new Error(`can't find ${req.originalUrl} on this server`));
});

app.use(globalErrorHandler);

module.exports = app;
