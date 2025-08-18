const jwt = require('jsonwebtoken');

const generateTokens = (payload) => {
  const accessToken = jwt.sign(
    payload,
    process.env.JWT_SECRET || 'fallback_secret',
    { expiresIn: process.env.JWT_EXPIRE || '15m' }
  );

  const refreshToken = jwt.sign(
    payload,
    process.env.JWT_REFRESH_SECRET || 'fallback_refresh_secret',
    { expiresIn: process.env.JWT_REFRESH_EXPIRE || '7d' }
  );

  return { accessToken, refreshToken };
};

const verifyAccessToken = (token) => {
  return jwt.verify(token, process.env.JWT_SECRET || 'fallback_secret');
};

const verifyRefreshToken = (token) => {
  return jwt.verify(token, process.env.JWT_REFRESH_SECRET || 'fallback_refresh_secret');
};

const decodeToken = (token) => {
  return jwt.decode(token);
};

const getTokenExpiration = (expiresIn) => {
  if (typeof expiresIn === 'string') {
    const unit = expiresIn.slice(-1);
    const value = parseInt(expiresIn.slice(0, -1));
    
    const multipliers = {
      's': 1000,
      'm': 60 * 1000,
      'h': 60 * 60 * 1000,
      'd': 24 * 60 * 60 * 1000
    };
    
    return new Date(Date.now() + value * (multipliers[unit] || 1000));
  }
  
  return new Date(Date.now() + (expiresIn * 1000));
};

module.exports = {
  generateTokens,
  verifyAccessToken,
  verifyRefreshToken,
  decodeToken,
  getTokenExpiration
}; 