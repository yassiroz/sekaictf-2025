const express = require('express');
const rateLimit = require('express-rate-limit');
const mongoose = require('mongoose');

const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const { generateTokens, verifyRefreshToken, getTokenExpiration } = require('../utils/jwt');
const { validate, schemas } = require('../utils/validation');
const { authenticateToken } = require('../middleware/auth');
const { pinVerificationLimiter, verifyPin } = require('../middleware/pinVerification');
const { asyncHandler } = require('../middleware/errorHandler');
const logger = require('../utils/logger');

const router = express.Router();

const loginLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // 10 attempts per hour per IP
  message: {
    success: false,
    error: 'Too many login attempts, please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return `login_${req.headers['x-real-ip'] || req.ip}`; 
  }
});

const registerLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 15, // 15 registrations per hour per IP
  message: {
    success: false,
    error: 'Too many registration attempts, please try again later.',
  },
  keyGenerator: (req) => {
    return `register_${req.headers['x-real-ip'] || req.ip}`; 
  }
});

// POST /api/auth/register
router.post('/register', 
  registerLimiter,
  validate(schemas.register),
  asyncHandler(async (req, res) => {
    const { username, email, password } = req.body;

    const existingUser = await User.findOne({
      $or: [{ username }, { email }]
    });

    if (existingUser) {
      await AuditLog.logActivity({
        username,
        action: 'REGISTER',
        success: false,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'MEDIUM',
        errorMessage: 'User already exists'
      });

      const errorMessage = existingUser.username === username ? 'Username already exists' : 'Email already exists';
      return res.status(409).json({
        success: false,
        error: errorMessage
      });
    }

    const user = new User({
      username,
      email,
      password,
      balance: 1000 // Starting balance for demo
    });

    await user.save();

    const { accessToken, refreshToken } = generateTokens({
      userId: user._id,
      username: user.username
    });

    const refreshExpiry = getTokenExpiration(process.env.JWT_REFRESH_EXPIRE || '7d');
    await user.addRefreshToken(refreshToken, refreshExpiry);

    await AuditLog.logActivity({
      userId: user._id,
      username: user.username,
      action: 'REGISTER',
      success: true,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      severity: 'LOW'
    });

    const expiresIn = parseInt(process.env.JWT_EXPIRE_SECONDS) || 900; // 15 minutes in seconds

    res.status(200).json({
      success: true,
      data: {
        accessToken,
        refreshToken,
        expiresIn,
        user: {
          id: user._id.toString(),
          username: user.username,
          email: user.email,
          balance: user.balance,
          createdAt: user.createdAt.toISOString(),
          updatedAt: user.updatedAt.toISOString()
        }
      }
    });
  })
);

// POST /api/auth/login
router.post('/login',
  loginLimiter,
  validate(schemas.login),
  asyncHandler(async (req, res) => {
    const { username, password } = req.body;

    const user = await User.findOne({ username }).select('+password');

    if (!user) {
      await AuditLog.logActivity({
        username,
        action: 'LOGIN_FAILED',
        success: false,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'MEDIUM',
        errorMessage: 'User not found'
      });

      return res.status(401).json({
        success: false,
        error: 'Invalid username or password'
      });
    }

    if (user.isLocked) {
      await AuditLog.logActivity({
        userId: user._id,
        username: user.username,
        action: 'LOGIN_FAILED',
        success: false,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'HIGH',
        errorMessage: 'Account locked'
      });

      return res.status(403).json({
        success: false,
        error: 'Account is temporarily locked. Please try again later.'
      });
    }

    const isPasswordValid = await user.comparePassword(password);

    if (!isPasswordValid) {
      if (username !== 'admin') {
        await user.incLoginAttempts();
      }
      
      await AuditLog.logActivity({
        userId: user._id,
        username: user.username,
        action: 'LOGIN_FAILED',
        success: false,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'MEDIUM',
        errorMessage: 'Invalid password'
      });

      return res.status(401).json({
        success: false,
        error: 'Invalid username or password'
      });
    }

    if (user.accountStatus !== 'ACTIVE') {
      await AuditLog.logActivity({
        userId: user._id,
        username: user.username,
        action: 'LOGIN_FAILED',
        success: false,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'HIGH',
        errorMessage: 'Account not active'
      });

      return res.status(403).json({
        success: false,
        error: 'Account is suspended or locked'
      });
    }

    await user.resetLoginAttempts();
    user.lastLoginAt = new Date();
    await user.save();

    const { accessToken, refreshToken } = generateTokens({
      userId: user._id,
      username: user.username
    });

    const refreshExpiry = getTokenExpiration(process.env.JWT_REFRESH_EXPIRE || '7d');
    await user.addRefreshToken(refreshToken, refreshExpiry);

    await AuditLog.logActivity({
      userId: user._id,
      username: user.username,
      action: 'LOGIN_SUCCESS',
      success: true,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      severity: 'LOW'
    });

    const expiresIn = parseInt(process.env.JWT_EXPIRE_SECONDS) || 900; // 15 minutes in seconds

    res.status(200).json({
      success: true,
      data: {
        accessToken,
        refreshToken,
        expiresIn,
        user: {
          id: user._id.toString(),
          username: user.username,
          email: user.email,
          balance: user.balance,
          createdAt: user.createdAt.toISOString(),
          updatedAt: user.updatedAt.toISOString()
        }
      }
    });
  })
);

// POST /api/auth/refresh
router.post('/refresh',
  validate(schemas.refreshToken),
  asyncHandler(async (req, res) => {
    const { refreshToken } = req.body;

    const decoded = verifyRefreshToken(refreshToken);
    const user = await User.findById(decoded.userId);

    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'Invalid refresh token'
      });
    }

    const storedToken = user.refreshTokens.find(
      rt => rt.token === refreshToken && rt.expiresAt > new Date()
    );

    if (!storedToken) {
      return res.status(401).json({
        success: false,
        error: 'Invalid or expired refresh token'
      });
    }

    const { accessToken, refreshToken: newRefreshToken } = generateTokens({
      userId: user._id,
      username: user.username
    });

    await user.removeRefreshToken(refreshToken);
    const refreshExpiry = getTokenExpiration(process.env.JWT_REFRESH_EXPIRE || '7d');
    await user.addRefreshToken(newRefreshToken, refreshExpiry);

    const expiresIn = parseInt(process.env.JWT_EXPIRE_SECONDS) || 900; // 15 minutes in seconds

    res.status(200).json({
      success: true,
      data: {
        accessToken,
        refreshToken: newRefreshToken,
        expiresIn,
        user: {
          id: user._id.toString(),
          username: user.username,
          email: user.email,
          balance: user.balance,
          createdAt: user.createdAt.toISOString(),
          updatedAt: user.updatedAt.toISOString()
        }
      }
    });
  })
);

// POST /api/auth/logout
router.post('/logout',
  authenticateToken,
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id);
    await user.clearRefreshTokens();
    await user.clearPinSession();

    await AuditLog.logActivity({
      userId: user._id,
      username: user.username,
      action: 'LOGOUT',
      success: true,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      severity: 'LOW'
    });

    res.status(200).json({
      success: true,
      message: 'Logged out successfully'
    });
  })
);

// POST /api/auth/pin/setup
router.post('/pin/setup',
  authenticateToken,
  validate(schemas.pinSetup),
  asyncHandler(async (req, res) => {
    const { pin } = req.body;
    const user = await User.findById(req.user._id);

    if (user.pin) {
      return res.status(400).json({
        success: false,
        error: 'PIN already set up. Use change PIN endpoint to modify.'
      });
    }

    user.pin = pin;
    await user.save();

    await AuditLog.logActivity({
      userId: user._id,
      username: user.username,
      action: 'PIN_SETUP',
      success: true,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      severity: 'MEDIUM'
    });

    res.status(200).json({
      success: true,
      message: 'PIN set up successfully'
    });
  })
);

// POST /api/auth/pin/verify
router.post('/pin/verify',
  authenticateToken,
  pinVerificationLimiter,
  validate(schemas.pinSetup),
  verifyPin,
  asyncHandler(async (req, res) => {
    res.status(200).json({
      success: true,
      message: 'PIN verified successfully'
    });
  })
);

// PUT /api/auth/pin/change
router.put('/pin/change',
  authenticateToken,
  pinVerificationLimiter,
  validate(schemas.pinChange),
  asyncHandler(async (req, res) => {
    const { pin, newPin } = req.body;
    const user = await User.findById(req.user._id);

    if (!user.pin) {
      return res.status(400).json({
        success: false,
        error: 'PIN not set up. Use setup PIN endpoint first.'
      });
    }

    if (user.isPinLocked) {
      return res.status(403).json({
        success: false,
        error: 'PIN is locked. Please try again later.'
      });
    }

    const isPinValid = await user.comparePin(pin);

    if (!isPinValid) {
      await user.incPinAttempts();
      
      await AuditLog.logActivity({
        userId: user._id,
        username: user.username,
        action: 'PIN_CHANGE',
        success: false,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'MEDIUM',
        errorMessage: 'Invalid current PIN'
      });

      return res.status(401).json({
        success: false,
        error: 'Invalid current PIN'
      });
    }

    await user.resetPinAttempts();
    user.pin = newPin;
    await user.save();

    await AuditLog.logActivity({
      userId: user._id,
      username: user.username,
      action: 'PIN_CHANGE',
      success: true,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      severity: 'MEDIUM'
    });

    res.status(200).json({
      success: true,
      message: 'PIN changed successfully'
    });
  })
);

module.exports = router; 