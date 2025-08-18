const Joi = require('joi');

const registerSchema = Joi.object({
  username: Joi.string()
    .alphanum()
    .min(3)
    .max(20)
    .pattern(/^[a-zA-Z0-9_]+$/)
    .required()
    .messages({
      'string.pattern.base': 'Username can only contain letters, numbers, and underscores'
    }),
  email: Joi.string()
    .email()
    .required(),
  password: Joi.string()
    .min(8)
    .pattern(/^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/)
    .required()
    .messages({
      'string.pattern.base': 'Password must contain at least one uppercase letter, one lowercase letter, one number, and one special character'
    })
});

const loginSchema = Joi.object({
  username: Joi.string()
    .required(),
  password: Joi.string()
    .required()
});

const pinSetupSchema = Joi.object({
  pin: Joi.string()
    .pattern(/^\d{6}$/)
    .required()
    .messages({
      'string.pattern.base': 'PIN must be exactly 6 digits'
    })
});

const pinChangeSchema = Joi.object({
  pin: Joi.string()
    .pattern(/^\d{6}$/)
    .required()
    .messages({
      'string.pattern.base': 'Current PIN must be exactly 6 digits'
    }),
  newPin: Joi.string()
    .pattern(/^\d{6}$/)
    .required()
    .messages({
      'string.pattern.base': 'New PIN must be exactly 6 digits'
    })
});

const refreshTokenSchema = Joi.object({
  refreshToken: Joi.string()
    .required()
});

const transactionSchema = Joi.object({
  toUsername: Joi.string()
    .alphanum()
    .min(3)
    .max(20)
    .pattern(/^[a-zA-Z0-9_]+$/)
    .required(),
  amount: Joi.number()
    .positive()
    .precision(2)
    .min(0.01)
    .max(1000000)
    .required(),
  message: Joi.string()
    .max(500)
    .allow('')
    .default(''),
  pin: Joi.string()
    .pattern(/^\d{6}$/)
    .required()
    .messages({
      'string.pattern.base': 'PIN must be exactly 6 digits'
    })
});

const paginationSchema = Joi.object({
  page: Joi.number()
    .integer()
    .min(1)
    .default(1),
  limit: Joi.number()
    .integer()
    .min(1)
    .max(100)
    .default(20)
});

const usernameParamSchema = Joi.object({
  username: Joi.string()
    .alphanum()
    .min(3)
    .max(20)
    .pattern(/^[a-zA-Z0-9_]+$/)
    .required()
});

const transactionIdSchema = Joi.object({
  id: Joi.string()
    .pattern(/^[0-9a-fA-F]{24}$/)
    .required()
    .messages({
      'string.pattern.base': 'Invalid transaction ID format'
    })
});

const validate = (schema, source = 'body') => {
  return (req, res, next) => {
    const data = source === 'params' ? req.params : 
                  source === 'query' ? req.query : req.body;
    
    const { error, value } = schema.validate(data, { 
      abortEarly: false,
      stripUnknown: true
    });

    if (error) {
      const errorMessage = error.details
        .map(detail => detail.message)
        .join(', ');
      
      return res.status(400).json({
        success: false,
        error: errorMessage
      });
    }

    if (source === 'params') req.params = value;
    else if (source === 'query') req.query = value;
    else req.body = value;

    next();
  };
};

module.exports = {
  validate,
  schemas: {
    register: registerSchema,
    login: loginSchema,
    pinSetup: pinSetupSchema,
    pinChange: pinChangeSchema,
    refreshToken: refreshTokenSchema,
    transaction: transactionSchema,
    pagination: paginationSchema,
    usernameParam: usernameParamSchema,
    transactionId: transactionIdSchema
  }
}; 