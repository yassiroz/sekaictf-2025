const mongoose = require('mongoose');

const auditLogSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true
  },
  username: {
    type: String,
    index: true
  },
  action: {
    type: String,
    required: true,
    enum: [
      'LOGIN_SUCCESS',
      'LOGIN_FAILED',
      'LOGOUT',
      'REGISTER',
      'PIN_SETUP',
      'PIN_CHANGE',
      'PIN_VERIFY_SUCCESS',
      'PIN_VERIFY_FAILED',
      'TRANSACTION_SEND',
      'TRANSACTION_RECEIVE',
      'BALANCE_CHECK',
      'PROFILE_VIEW',
      'PROFILE_UPDATE',
      'USER_SEARCH',
      'ACCOUNT_LOCKED',
      'ACCOUNT_UNLOCKED',
      'PASSWORD_CHANGE',
      'SUSPICIOUS_ACTIVITY'
    ],
    index: true
  },
  details: {
    type: Object,
    default: {}
  },
  ipAddress: {
    type: String,
    index: true
  },
  userAgent: {
    type: String
  },
  sessionId: {
    type: String,
    index: true
  },
  success: {
    type: Boolean,
    default: true,
    index: true
  },
  errorMessage: {
    type: String
  },
  severity: {
    type: String,
    enum: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'],
    default: 'LOW',
    index: true
  },
  metadata: {
    endpoint: String,
    method: String,
    responseTime: Number,
    statusCode: Number
  }
}, {
  timestamps: true
});

auditLogSchema.index({ createdAt: -1 });
auditLogSchema.index({ userId: 1, createdAt: -1 });
auditLogSchema.index({ action: 1, createdAt: -1 });
auditLogSchema.index({ severity: 1, createdAt: -1 });

auditLogSchema.statics.logActivity = function(data) {
  return this.create({
    userId: data.userId,
    username: data.username,
    action: data.action,
    details: data.details || {},
    ipAddress: data.ipAddress,
    userAgent: data.userAgent,
    sessionId: data.sessionId,
    success: data.success !== false,
    errorMessage: data.errorMessage,
    severity: data.severity || 'LOW',
    metadata: data.metadata || {}
  });
};

auditLogSchema.statics.getUserActivity = function(userId, page = 1, limit = 50) {
  const skip = (page - 1) * limit;
  
  return this.find({ userId })
    .sort({ createdAt: -1 })
    .skip(skip)
    .limit(limit)
    .select('-__v');
};

auditLogSchema.statics.getSecurityEvents = function(severity = 'HIGH', hours = 24) {
  const since = new Date(Date.now() - (hours * 60 * 60 * 1000));
  
  return this.find({
    severity: { $in: Array.isArray(severity) ? severity : [severity] },
    createdAt: { $gte: since }
  })
  .sort({ createdAt: -1 })
  .populate('userId', 'username email');
};

auditLogSchema.statics.getSuspiciousActivity = function(hours = 24) {
  const since = new Date(Date.now() - (hours * 60 * 60 * 1000));
  
  return this.aggregate([
    {
      $match: {
        createdAt: { $gte: since },
        action: { $in: ['LOGIN_FAILED', 'PIN_VERIFY_FAILED'] }
      }
    },
    {
      $group: {
        _id: {
          userId: '$userId',
          ipAddress: '$ipAddress'
        },
        count: { $sum: 1 },
        actions: { $push: '$action' },
        lastAttempt: { $max: '$createdAt' }
      }
    },
    {
      $match: {
        count: { $gte: 5 }
      }
    },
    {
      $sort: { count: -1 }
    }
  ]);
};

module.exports = mongoose.model('AuditLog', auditLogSchema); 