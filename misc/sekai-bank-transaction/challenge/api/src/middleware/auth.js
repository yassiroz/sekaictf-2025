const { verifyAccessToken } = require('../utils/jwt');
const User = require('../models/User');
const AuditLog = require('../models/AuditLog');
const logger = require('../utils/logger');

const authenticateToken = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Access token required'
      });
    }

    const decoded = verifyAccessToken(token);
    const user = await User.findById(decoded.userId).select('-password -pin -refreshTokens');

    if (!user) {
      return res.status(401).json({
        success: false,
        error: 'User not found'
      });
    }

    if (user.accountStatus !== 'ACTIVE') {
      await AuditLog.logActivity({
        userId: user._id,
        username: user.username,
        action: 'ACCOUNT_LOCKED',
        success: false,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'HIGH'
      });

      return res.status(403).json({
        success: false,
        error: 'Account is locked or suspended'
      });
    }

    if (user.isLocked) {
      return res.status(403).json({
        success: false,
        error: 'Account is temporarily locked due to too many failed attempts'
      });
    }

    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    logger.error('Authentication error:', error);

    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({
        success: false,
        error: 'Token expired'
      });
    }

    if (error.name === 'JsonWebTokenError') {
      return res.status(401).json({
        success: false,
        error: 'Invalid token'
      });
    }

    return res.status(500).json({
      success: false,
      error: 'Authentication failed'
    });
  }
};

const optionalAuth = async (req, res, next) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (token) {
      const decoded = verifyAccessToken(token);
      const user = await User.findById(decoded.userId).select('-password -pin -refreshTokens');
      
      if (user && user.accountStatus === 'ACTIVE' && !user.isLocked) {
        req.user = user;
        req.token = token;
      }
    }
    
    next();
  } catch (error) {
    next();
  }
};

module.exports = {
  authenticateToken,
  optionalAuth
}; 