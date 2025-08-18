const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const mongoSanitize = require('express-mongo-sanitize');
const rateLimit = require('express-rate-limit');

const authRoutes = require('./routes/auth');
const userRoutes = require('./routes/user');
const transactionRoutes = require('./routes/transactions');
const healthRoutes = require('./routes/health');
const { errorHandler } = require('./middleware/errorHandler');
const { verifySignature } = require('./middleware/signatureVerification');
const logger = require('./utils/logger');

const app = express();

// Database connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/sekaibank', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});

mongoose.connection.on('connected', () => {
  logger.info('Connected to MongoDB');
});

mongoose.connection.on('error', (err) => {
  logger.error('MongoDB connection error:', err);
});

// Security middleware
app.use(helmet());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS || '*',
  credentials: true,
}));

// Rate limiting
const limiter = rateLimit({
  windowMs: parseInt(process.env.RATE_LIMIT_WINDOW) || 15 * 60 * 1000,
  max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100,
  message: {
    success: false,
    error: 'Too many requests from this IP, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return `rate_limit_${req.headers['x-real-ip'] || req.ip}`; 
  }
});

app.use(limiter);

// Body parsing and sanitization
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));
app.use(mongoSanitize());

// app.use('/api', verifySignature);

// Request logging
app.use((req, res, next) => {
  logger.info(`${req.method} ${req.path} - ${req.ip}`);
  next();
});

// Routes
app.use('/api/health', healthRoutes);
app.use('/api/auth', authRoutes);
app.use('/api/user', userRoutes);
app.use('/api/transactions', transactionRoutes);


// Flag
app.post('/api/flag', verifySignature, (req, res) => {
  const { unmask_flag } = req.body;
  if (unmask_flag === true) {
    res.send(process.env.FLAG1);
  } else {
    res.send('SEKAI{*************************************}');
  }
});

// 404 handler
app.use('*', (req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route not found',
  });
});

// Error handling middleware
app.use(errorHandler);

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  logger.info(`SekaiBank server running on port ${PORT}`);
});

module.exports = app; 