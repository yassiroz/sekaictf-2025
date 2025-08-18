const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');

const requirePinSession = async (req, res, next) => {
  try {
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
        errorMessage: 'PIN not set up - session access denied'
      });

      return res.status(400).json({
        success: false,
        error: 'PIN not set up. Please set up your PIN to access this feature.',
        requiresPinSetup: true
      });
    }

    if (!user.isPinSessionValid) {
      await AuditLog.logActivity({
        userId: user._id,
        username: user.username,
        action: 'PIN_VERIFY_FAILED',
        success: false,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'MEDIUM',
        errorMessage: 'PIN session expired or not verified'
      });

      return res.status(403).json({
        success: false,
        error: 'PIN verification required. Please verify your PIN to access this feature.',
        requiresPinVerification: true
      });
    }

    req.user = user;
    next();
  } catch (error) {
    logger.error('PIN session verification error:', error);
    
    return res.status(500).json({
      success: false,
      error: 'Session verification failed'
    });
  }
};

module.exports = {
  requirePinSession
}; 