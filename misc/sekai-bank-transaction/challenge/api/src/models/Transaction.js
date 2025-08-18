const mongoose = require('mongoose');

const transactionSchema = new mongoose.Schema({
  referenceId: {
    type: String,
    required: true,
    unique: true,
    default: () => `TXN${Date.now()}${Math.floor(Math.random() * 1000)}`
  },
  fromUserId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  toUserId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  fromUsername: {
    type: String,
    required: true
  },
  toUsername: {
    type: String,
    required: true
  },
  amount: {
    type: Number,
    required: true,
    min: 0.01,
    max: 1000000,
    validate: {
      validator: function(value) {
        return Number(value.toFixed(2)) === value;
      },
      message: 'Amount can have at most 2 decimal places'
    }
  },
  fee: {
    type: Number,
    default: 0,
    min: 0
  },
  exchangeRate: {
    type: Number,
    default: 1,
    min: 0
  },
  message: {
    type: String,
    trim: true,
    maxlength: 500,
    default: ''
  },
  status: {
    type: String,
    enum: ['PENDING', 'COMPLETED', 'FAILED', 'CANCELLED'],
    default: 'PENDING'
  },
  type: {
    type: String,
    enum: ['TRANSFER', 'DEPOSIT', 'WITHDRAWAL', 'FEE'],
    default: 'TRANSFER'
  },
  failureReason: {
    type: String,
    trim: true
  },
  balanceAfter: {
    sender: Number,
    receiver: Number
  },
  metadata: {
    type: Object,
    default: {}
  },
  processedAt: {
    type: Date
  },
  sessionId: {
    type: String
  }
}, {
  timestamps: true
});

transactionSchema.index({ fromUserId: 1, createdAt: -1 });
transactionSchema.index({ toUserId: 1, createdAt: -1 });
transactionSchema.index({ referenceId: 1 });
transactionSchema.index({ status: 1 });
transactionSchema.index({ createdAt: -1 });

transactionSchema.methods.markCompleted = function(senderBalance, receiverBalance) {
  this.status = 'COMPLETED';
  this.processedAt = new Date();
  this.balanceAfter = {
    sender: senderBalance,
    receiver: receiverBalance
  };
  return this.save();
};

transactionSchema.methods.markFailed = function(reason) {
  this.status = 'FAILED';
  this.processedAt = new Date();
  this.failureReason = reason;
  return this.save();
};

transactionSchema.statics.getUserTransactions = function(userId, page = 1, limit = 20) {
  const skip = (page - 1) * limit;
  
  return this.find({
    $or: [
      { fromUserId: userId },
      { toUserId: userId }
    ]
  })
  .sort({ createdAt: -1 })
  .skip(skip)
  .limit(limit)
  .populate('fromUserId', 'username')
  .populate('toUserId', 'username');
};

transactionSchema.statics.getTransactionStats = function(userId, startDate, endDate) {
  const matchStage = {
    $or: [
      { fromUserId: mongoose.Types.ObjectId(userId) },
      { toUserId: mongoose.Types.ObjectId(userId) }
    ],
    status: 'COMPLETED'
  };

  if (startDate && endDate) {
    matchStage.createdAt = {
      $gte: new Date(startDate),
      $lte: new Date(endDate)
    };
  }

  return this.aggregate([
    { $match: matchStage },
    {
      $group: {
        _id: null,
        totalTransactions: { $sum: 1 },
        totalSent: {
          $sum: {
            $cond: [
              { $eq: ['$fromUserId', mongoose.Types.ObjectId(userId)] },
              '$amount',
              0
            ]
          }
        },
        totalReceived: {
          $sum: {
            $cond: [
              { $eq: ['$toUserId', mongoose.Types.ObjectId(userId)] },
              '$amount',
              0
            ]
          }
        }
      }
    }
  ]);
};

transactionSchema.methods.toJSON = function() {
  const transactionObject = this.toObject();
  delete transactionObject.__v;
  return transactionObject;
};

module.exports = mongoose.model('Transaction', transactionSchema); 