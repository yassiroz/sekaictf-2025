const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 20,
    match: /^[a-zA-Z0-9_]+$/
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
    match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/
  },
  password: {
    type: String,
    required: true,
    minlength: 8
  },
  balance: {
    type: Number,
    default: 0,
    min: 0
  },
  pin: {
    type: String,
    default: null
  },
  pinAttempts: {
    type: Number,
    default: 0
  },
  pinLockedUntil: {
    type: Date,
    default: null
  },
  lastLoginAt: {
    type: Date,
    default: null
  },
  isEmailVerified: {
    type: Boolean,
    default: false
  },
  accountStatus: {
    type: String,
    enum: ['ACTIVE', 'SUSPENDED', 'LOCKED'],
    default: 'ACTIVE'
  },
  refreshTokens: [{
    token: String,
    createdAt: { type: Date, default: Date.now },
    expiresAt: Date
  }],
  pinVerifiedAt: {
    type: Date,
    default: null
  },
  pinSessionExpiry: {
    type: Date,
    default: null
  },
  loginAttempts: {
    type: Number,
    default: 0
  },
  lockUntil: {
    type: Date,
    default: null
  }
}, {
  timestamps: true
});

userSchema.virtual('isLocked').get(function() {
  return !!(this.lockUntil && this.lockUntil > Date.now());
});

userSchema.virtual('isPinLocked').get(function() {
  return !!(this.pinLockedUntil && this.pinLockedUntil > Date.now());
});

userSchema.virtual('isPinSessionValid').get(function() {
  return !!(this.pinVerifiedAt && this.pinSessionExpiry && this.pinSessionExpiry > Date.now());
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(parseInt(process.env.BCRYPT_ROUNDS) || 12);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.pre('save', async function(next) {
  if (!this.isModified('pin') || !this.pin) return next();
  
  try {
    const salt = await bcrypt.genSalt(parseInt(process.env.BCRYPT_ROUNDS) || 12);
    this.pin = await bcrypt.hash(this.pin, salt);
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.comparePassword = async function(candidatePassword) {
  return bcrypt.compare(candidatePassword, this.password);
};

userSchema.methods.comparePin = async function(candidatePin) {
  if (!this.pin) return false;
  return bcrypt.compare(candidatePin, this.pin);
};

userSchema.methods.incLoginAttempts = function() {
  if (this.lockUntil && this.lockUntil < Date.now()) {
    return this.updateOne({
      $unset: { lockUntil: 1 },
      $set: { loginAttempts: 1 }
    });
  }

  const updates = { $inc: { loginAttempts: 1 } };
  
  if (this.loginAttempts + 1 >= 5 && !this.isLocked) {
    updates.$set = { lockUntil: Date.now() + 2 * 60 * 60 * 1000 }; // 2 hours
  }
  
  return this.updateOne(updates);
};

userSchema.methods.incPinAttempts = function() {
  if (this.pinLockedUntil && this.pinLockedUntil < Date.now()) {
    return this.updateOne({
      $unset: { pinLockedUntil: 1 },
      $set: { pinAttempts: 1 }
    });
  }

  const updates = { $inc: { pinAttempts: 1 } };
  const maxAttempts = parseInt(process.env.PIN_MAX_ATTEMPTS) || 3;
  const lockDuration = parseInt(process.env.PIN_LOCK_DURATION) || 3600000; // 1 hour
  
  if (this.pinAttempts + 1 >= maxAttempts && !this.isPinLocked) {
    updates.$set = { pinLockedUntil: Date.now() + lockDuration };
  }
  
  return this.updateOne(updates);
};

userSchema.methods.resetLoginAttempts = function() {
  return this.updateOne({
    $unset: { loginAttempts: 1, lockUntil: 1 }
  });
};

userSchema.methods.resetPinAttempts = function() {
  return this.updateOne({
    $unset: { pinAttempts: 1, pinLockedUntil: 1 }
  });
};

userSchema.methods.setPinSessionValid = function() {
  const sessionDuration = parseInt(process.env.PIN_SESSION_DURATION) || 30 * 60 * 1000; // 30 minutes default
  this.pinVerifiedAt = new Date();
  this.pinSessionExpiry = new Date(Date.now() + sessionDuration);
  return this.save();
};

userSchema.methods.clearPinSession = function() {
  return this.updateOne({
    $unset: { pinVerifiedAt: 1, pinSessionExpiry: 1 }
  });
};

userSchema.methods.addRefreshToken = function(token, expiresAt) {
  this.refreshTokens.push({ token, expiresAt });
  return this.save();
};

userSchema.methods.removeRefreshToken = function(token) {
  this.refreshTokens = this.refreshTokens.filter(rt => rt.token !== token);
  return this.save();
};

userSchema.methods.clearRefreshTokens = function() {
  this.refreshTokens = [];
  return this.save();
};

userSchema.methods.toJSON = function() {
  const userObject = this.toObject();
  delete userObject.password;
  delete userObject.pin;
  delete userObject.refreshTokens;
  delete userObject.__v;
  return userObject;
};

module.exports = mongoose.model('User', userSchema); 