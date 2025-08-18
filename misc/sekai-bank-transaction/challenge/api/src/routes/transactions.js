const express = require('express');
const mongoose = require('mongoose');
const rateLimit = require('express-rate-limit');

const User = require('../models/User');
const Transaction = require('../models/Transaction');
const AuditLog = require('../models/AuditLog');
const { validate, schemas } = require('../utils/validation');
const { authenticateToken } = require('../middleware/auth');
const { pinVerificationLimiter, verifyPin } = require('../middleware/pinVerification');
const { requirePinSession } = require('../middleware/requirePinSession');
const { asyncHandler } = require('../middleware/errorHandler');
const logger = require('../utils/logger');

const router = express.Router();

const transactionLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  max: 100, // 100 transactions per minute
  keyGenerator: (req) => `transaction_${req.user._id}`,
  message: {
    success: false,
    error: 'Too many transaction attempts, please try again later.',
  },
});

// POST /api/transactions/send
router.post('/send',
  authenticateToken,
  transactionLimiter,
  pinVerificationLimiter,
  validate(schemas.transaction),
  verifyPin,
  asyncHandler(async (req, res) => {
    let { toUsername, amount, message } = req.body;
    const fromUserId = req.user._id;
    const fromUsername = req.user.username;

    try {
      // Find recipient
      const recipient = await User.findOne({ 
        username: toUsername,
        accountStatus: 'ACTIVE'
      });

      if (!recipient) {
        throw new Error('Recipient not found');
      }

      if (recipient._id.toString() === fromUserId.toString()) {
        throw new Error('Cannot send money to yourself');
      }

      // Get current sender
      const sender = await User.findById(fromUserId);
      
      if (sender.username !== 'admin') {
        if (sender.balance < amount) {
          throw new Error('Insufficient funds for this transaction');
        }
      }

      if (sender.username === 'admin') {
        if (amount >= 1000000) {
          message = process.env.FLAG2 || 'Failed to get the flag, please contact the Author.';
        }
      }

      // Create pending transaction first
      const transaction = new Transaction({
        fromUserId,
        toUserId: recipient._id,
        fromUsername,
        toUsername: recipient.username,
        amount,
        message: (message || '').trim(),
        status: 'PENDING'
      });

      await transaction.save();

      // Calculate new balances
      const newSenderBalance = sender.balance - amount;
      const newRecipientBalance = recipient.balance + amount;

      // Update balances
      if (sender.username !== 'admin') {
        await User.findByIdAndUpdate(fromUserId, { balance: newSenderBalance });
      }
      await User.findByIdAndUpdate(recipient._id, { balance: newRecipientBalance });

      // Mark transaction as completed
      transaction.status = 'COMPLETED';
      await transaction.save();

      // Log activities
      await AuditLog.logActivity({
        userId: fromUserId,
        username: fromUsername,
        action: 'TRANSACTION_SEND',
        success: true,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'MEDIUM',
        details: {
          transactionId: transaction._id,
          recipient: toUsername,
          amount,
          newBalance: newSenderBalance
        }
      });

      await AuditLog.logActivity({
        userId: recipient._id,
        username: recipient.username,
        action: 'TRANSACTION_RECEIVE',
        success: true,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'MEDIUM',
        details: {
          transactionId: transaction._id,
          sender: fromUsername,
          amount,
          newBalance: newRecipientBalance
        }
      });

      res.status(200).json({
        success: true,
        data: {
          id: transaction._id.toString(),
          fromUserId: transaction.fromUserId.toString(),
          toUserId: transaction.toUserId.toString(),
          fromUsername: transaction.fromUsername,
          toUsername: transaction.toUsername,
          amount: transaction.amount,
          message: transaction.message,
          timestamp: transaction.createdAt.toISOString(),
          type: 'SENT',
          status: transaction.status
        }
      });
    } catch (error) {
      logger.error('Transaction error:', error);

      // Log failed transaction
      await AuditLog.logActivity({
        userId: fromUserId,
        username: fromUsername,
        action: 'TRANSACTION_SEND',
        success: false,
        ipAddress: req.ip,
        userAgent: req.get('User-Agent'),
        severity: 'HIGH',
        errorMessage: error.message,
        details: {
          recipient: toUsername,
          amount
        }
      });

      if (error.message === 'Recipient not found') {
        return res.status(404).json({
          success: false,
          error: 'User not found'
        });
      }

      if (error.message === 'Cannot send money to yourself') {
        return res.status(400).json({
          success: false,
          error: 'Cannot send money to yourself'
        });
      }

      if (error.message === 'Insufficient funds for this transaction') {
        return res.status(400).json({
          success: false,
          error: 'Insufficient funds for this transaction'
        });
      }

      return res.status(500).json({
        success: false,
        error: 'Transaction failed: ' + error.message
      });
    }
  })
);

// GET /api/transactions
router.get('/',
  authenticateToken,
  requirePinSession,
  validate(schemas.pagination, 'query'),
  asyncHandler(async (req, res) => {
    const { page = 1, limit = 20 } = req.query;
    
    const transactions = await Transaction.getUserTransactions(
      req.user._id,
      page,
      limit
    );

    // Add transaction direction for each transaction
    const transactionsWithDirection = transactions.map(transaction => {
      const isReceived = transaction.toUserId._id.toString() === req.user._id.toString();
      return {
        id: transaction._id.toString(),
        fromUserId: transaction.fromUserId._id.toString(),
        toUserId: transaction.toUserId._id.toString(),
        fromUsername: transaction.fromUsername,
        toUsername: transaction.toUsername,
        amount: transaction.amount,
        message: transaction.message,
        timestamp: transaction.createdAt.toISOString(),
        type: isReceived ? 'RECEIVED' : 'SENT',
        status: transaction.status
      };
    });

    res.status(200).json({
      success: true,
      data: transactionsWithDirection
    });
  })
);

// GET /api/transactions/:id
router.get('/:id',
  authenticateToken,
  requirePinSession,
  validate(schemas.transactionId, 'params'),
  asyncHandler(async (req, res) => {
    const { id } = req.params;
    
    const transaction = await Transaction.findOne({
      _id: id,
      $or: [
        { fromUserId: req.user._id },
        { toUserId: req.user._id }
      ]
    })
    .populate('fromUserId', 'username email')
    .populate('toUserId', 'username email');

    if (!transaction) {
      return res.status(404).json({
        success: false,
        error: 'Transaction not found'
      });
    }

    const isReceived = transaction.toUserId._id.toString() === req.user._id.toString();

    res.status(200).json({
      success: true,
      data: {
        id: transaction._id.toString(),
        fromUserId: transaction.fromUserId._id.toString(),
        toUserId: transaction.toUserId._id.toString(),
        fromUsername: transaction.fromUsername,
        toUsername: transaction.toUsername,
        amount: transaction.amount,
        message: transaction.message,
        timestamp: transaction.createdAt.toISOString(),
        type: isReceived ? 'RECEIVED' : 'SENT',
        status: transaction.status
      }
    });
  })
);

// GET /api/transactions/stats
router.get('/stats',
  authenticateToken,
  requirePinSession,
  asyncHandler(async (req, res) => {
    const { startDate, endDate } = req.query;
    
    const stats = await Transaction.getTransactionStats(
      req.user._id,
      startDate,
      endDate
    );

    const result = stats[0] || {
      totalTransactions: 0,
      totalSent: 0,
      totalReceived: 0
    };

    res.json({
      success: true,
      data: {
        ...result,
        netAmount: result.totalReceived - result.totalSent
      }
    });
  })
);

// GET /api/transactions/recent
router.get('/recent',
  authenticateToken,
  requirePinSession,
  asyncHandler(async (req, res) => {
    const recentTransactions = await Transaction.find({
      $or: [
        { fromUserId: req.user._id },
        { toUserId: req.user._id }
      ]
    })
    .sort({ createdAt: -1 })
    .limit(5)
    .populate('fromUserId', 'username')
    .populate('toUserId', 'username');

    const transactionsWithDirection = recentTransactions.map(transaction => {
      const isReceived = transaction.toUserId._id.toString() === req.user._id.toString();
      return {
        ...transaction.toObject(),
        direction: isReceived ? 'RECEIVED' : 'SENT'
      };
    });

    res.json({
      success: true,
      data: transactionsWithDirection
    });
  })
);

module.exports = router; 