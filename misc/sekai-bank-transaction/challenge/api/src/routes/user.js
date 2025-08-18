const express = require('express');
const rateLimit = require('express-rate-limit');

const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const { validate, schemas } = require('../utils/validation');
const { authenticateToken } = require('../middleware/auth');
const { requirePinSession } = require('../middleware/requirePinSession');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

const userSearchLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 10, // 10 searches per minute
  // keyGenerator: (req) => `user_search_${req.user._id}`,
  message: {
    success: false,
    error: 'Too many search requests, please try again later.',
  },
  keyGenerator: (req) => {
    return `user_search_${req.user._id}_${req.headers['x-real-ip'] || req.ip}`; 
  }
});

const balanceCheckLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 20, // 20 balance checks per minute
  // keyGenerator: (req) => `balance_check_${req.user._id}`,
  message: {
    success: false,
    error: 'Too many balance check requests, please try again later.',
  },
  keyGenerator: (req) => {
    return `balance_check_${req.user._id}_${req.headers['x-real-ip'] || req.ip}`; 
  }
});

// GET /api/user/profile
router.get('/profile',
  authenticateToken,
  requirePinSession,
  asyncHandler(async (req, res) => {
    await AuditLog.logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'PROFILE_VIEW',
      success: true,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      severity: 'LOW'
    });

    res.status(200).json({
      success: true,
      data: {
        id: req.user._id.toString(),
        username: req.user.username,
        email: req.user.email,
        balance: req.user.balance,
        createdAt: req.user.createdAt.toISOString(),
        updatedAt: req.user.updatedAt.toISOString()
      }
    });
  })
);

// GET /api/user/balance
router.get('/balance',
  authenticateToken,
  requirePinSession,
  balanceCheckLimiter,
  asyncHandler(async (req, res) => {
    const user = await User.findById(req.user._id).select('balance');

    await AuditLog.logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'BALANCE_CHECK',
      success: true,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      severity: 'LOW',
      details: {
        balance: user.balance
      }
    });

    res.status(200).json({
      success: true,
      data: {
        balance: user.balance
      }
    });
  })
);

// GET /api/user/search/{username}
router.get('/search/:username',
  authenticateToken,
  requirePinSession,
  userSearchLimiter,
  validate(schemas.usernameParam, 'params'),
  asyncHandler(async (req, res) => {
    const { username } = req.params;

    if (username === req.user.username) {
      return res.status(400).json({
        success: false,
        error: 'Cannot search for yourself'
      });
    }

    const user = await User.findOne({ 
      username,
      accountStatus: 'ACTIVE'
    }).select('username email createdAt updatedAt');

    if (!user) {
      return res.status(404).json({
        success: false,
        error: 'User not found'
      });
    }

    await AuditLog.logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'USER_SEARCH',
      success: true,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      severity: 'LOW',
      details: {
        searchedUser: username
      }
    });

    res.status(200).json({
      success: true,
      data: {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        createdAt: user.createdAt.toISOString(),
        updatedAt: user.updatedAt.toISOString()
      }
    });
  })
);

// PUT /api/user/profile
router.put('/profile',
  authenticateToken,
  requirePinSession,
  asyncHandler(async (req, res) => {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({
        success: false,
        error: 'Email is required'
      });
    }

    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid email format'
      });
    }

    const existingUser = await User.findOne({ 
      email, 
      _id: { $ne: req.user._id } 
    });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        error: 'Email already in use'
      });
    }

    const user = await User.findByIdAndUpdate(
      req.user._id,
      { email },
      { new: true, runValidators: true }
    ).select('-password -pin -refreshTokens');

    await AuditLog.logActivity({
      userId: req.user._id,
      username: req.user.username,
      action: 'PROFILE_UPDATE',
      success: true,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      severity: 'MEDIUM',
      details: {
        updatedFields: ['email']
      }
    });

    res.status(200).json({
      success: true,
      data: {
        id: user._id.toString(),
        username: user.username,
        email: user.email,
        balance: user.balance,
        createdAt: user.createdAt.toISOString(),
        updatedAt: user.updatedAt.toISOString()
      }
    });
  })
);

// GET /api/user/activity
router.get('/activity',
  authenticateToken,
  validate(schemas.pagination, 'query'),
  asyncHandler(async (req, res) => {
    const { page, limit } = req.query;
    
    const activities = await AuditLog.getUserActivity(req.user._id, page, limit);

    res.status(200).json({
      success: true,
      data: activities
    });
  })
);

module.exports = router; 