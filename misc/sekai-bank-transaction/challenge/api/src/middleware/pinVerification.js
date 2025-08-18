const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const rateLimit = require('express-rate-limit');
const logger = require('../utils/logger');

const pinVerificationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 1000, // 10 attempts per hour per IP
  // keyGenerator: (req) => `pin_verify_${req.user._id}_${req.ip}`,
  message: {
    success: false,
    error: 'Too many PIN verification attempts. Please try again later.',
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => {
    return `pin_verify_${req.user._id}_${req.headers['x-real-ip'] || req.ip}`; 
  }
});

const verifyPin = async (req, res, next) => {
  try {
    const { pin } = req.body;
    const user = await User.findById(req.user._id);

    if (!user.pin) {
      await AuditLog.logActivity({
        userId: user._id,
        username: user.username,
        action: 'PIN_VERIFY_FAILED',
        success: false,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'MEDIUM',
        errorMessage: 'PIN not set up'
      });

      return res.status(400).json({
        success: false,
        error: 'PIN not set up. Please set up your PIN first.'
      });
    }

    if (user.isPinLocked) {
      await AuditLog.logActivity({
        userId: user._id,
        username: user.username,
        action: 'PIN_VERIFY_FAILED',
        success: false,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'HIGH',
        errorMessage: 'PIN locked'
      });

      return res.status(403).json({
        success: false,
        error: 'PIN is locked due to too many failed attempts. Please try again later.'
      });
    }

    const isPinValid = await user.comparePin(pin);

    if (!isPinValid) {
      // await user.incPinAttempts();
      
      await AuditLog.logActivity({
        userId: user._id,
        username: user.username,
        action: 'PIN_VERIFY_FAILED',
        success: false,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'MEDIUM',
        details: {
          attempts: user.pinAttempts + 1
        }
      });

      return res.status(401).json({
        success: false,
        error: 'Invalid PIN'
      });
    }

    await user.resetPinAttempts();
    await user.setPinSessionValid();
    
    await AuditLog.logActivity({
      userId: user._id,
      username: user.username,
      action: 'PIN_VERIFY_SUCCESS',
      success: true,
      ipAddress: req.ip,
      userAgent: req.get('User-Agent'),
      severity: 'LOW'
    });

    next();
  } catch (error) {
    logger.error('PIN verification error:', error);
    
    return res.status(500).json({
      success: false,
      error: 'PIN verification failed'
    });
  }
};

module.exports = {
  pinVerificationLimiter,
  verifyPin
}; 