const crypto = require('crypto');
const logger = require('../utils/logger');

const HMAC_SECRET = Buffer.from([
  0x3F, 0x3C, 0xF8, 0x83, 0x0A, 0xCC, 0x96, 0x53, 0x0D, 0x55, 0x64, 0x31, 0x7F, 0xE4, 0x80, 0xAB, 0x58, 0x1D, 0xFC, 0x55, 0xEC, 0x8F, 0xE5, 0x5E, 0x67, 0xDD, 0xDB, 0xE1, 0xFD, 0xB6, 0x05, 0xBE
])

/**
 * X-Signature Verification Middleware
 * 
 * Validates the X-Signature header which should contain an HMAC-SHA256 hash
 * of the concatenated string: METHOD + Endpoint + Body Data
 * using key '123' for testing.
 */
const verifySignature = (req, res, next) => {
  try {
    const providedSignature = req.headers['x-signature'];

    if (!providedSignature) {
      return res.status(401).json({
        success: false,
        error: 'X-Signature header is required'
      });
    }

    const method = req.method;
    const endpoint = req.originalUrl;
    let bodyData = req.body || '';

    try {
      bodyData = JSON.stringify(bodyData);
    } catch (_) {
      bodyData = bodyData;
    }

    const signatureString = `${method}${endpoint}${bodyData}`;

    const expectedSignature = crypto
      .createHmac('sha256', HMAC_SECRET)
      .update(signatureString)
      .digest('hex');

    if (providedSignature.toLowerCase() !== expectedSignature.toLowerCase()) {
      logger.warn('Invalid signature attempt:', {
        ip: req.ip,
        method,
        endpoint,
        providedSignature,
        expectedSignature,
        signatureString
      });

      return res.status(401).json({
        success: false,
        error: 'Invalid signature'
      });
    }

    logger.info('Signature verified successfully:', {
      ip: req.ip,
      method,
      endpoint
    });

    next();
  } catch (error) {
    logger.error('Signature verification error:', error);
    return res.status(500).json({
      success: false,
      error: 'Signature verification failed'
    });
  }
};

module.exports = {
  verifySignature
};
