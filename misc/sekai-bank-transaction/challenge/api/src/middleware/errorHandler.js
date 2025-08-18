const logger = require('../utils/logger');

const errorHandler = (err, req, res, next) => {
  let error = { ...err };
  error.message = err.message;

  logger.error('Error:', {
    message: err.message,
    stack: err.stack,
    url: req.url,
    method: req.method,
    ip: req.ip,
    userAgent: req.get('User-Agent'),
    user: req.user ? req.user.id : 'Anonymous'
  });

  // Sequelize validation error
  if (err.name === 'SequelizeValidationError') {
    const message = err.errors.map(e => e.message).join(', ');
    error = { message, statusCode: 400 };
  }

  // Sequelize unique constraint error
  if (err.name === 'SequelizeUniqueConstraintError') {
    const field = err.errors[0]?.path || 'field';
    const message = field === 'username' ? 'Username already exists' : 
                   field === 'email' ? 'Email already exists' : 
                   `${field.charAt(0).toUpperCase() + field.slice(1)} already exists`;
    error = { message, statusCode: 409 };
  }

  // Sequelize foreign key constraint error
  if (err.name === 'SequelizeForeignKeyConstraintError') {
    const message = 'Referenced resource does not exist';
    error = { message, statusCode: 400 };
  }

  // Sequelize database error
  if (err.name === 'SequelizeDatabaseError') {
    const message = 'Database operation failed';
    error = { message, statusCode: 500 };
  }

  // Sequelize connection error
  if (err.name === 'SequelizeConnectionError' || err.name === 'SequelizeConnectionRefusedError') {
    const message = 'Database connection error';
    error = { message, statusCode: 503 };
  }

  // JWT errors
  if (err.name === 'JsonWebTokenError') {
    const message = 'Invalid token';
    error = { message, statusCode: 401 };
  }

  if (err.name === 'TokenExpiredError') {
    const message = 'Token expired';
    error = { message, statusCode: 401 };
  }

  // Rate limit errors
  if (err.status === 429) {
    const message = 'Too many requests, please try again later';
    error = { message, statusCode: 429 };
  }

  // Default to 500 server error
  const statusCode = error.statusCode || 500;
  const message = error.message || 'Internal Server Error';

  res.status(statusCode).json({
    success: false,
    error: message,
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
};

const notFound = (req, res, next) => {
  const error = new Error(`Route ${req.originalUrl} not found`);
  res.status(404);
  next(error);
};

const asyncHandler = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

module.exports = {
  errorHandler,
  notFound,
  asyncHandler
}; 