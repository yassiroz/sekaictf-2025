const express = require('express');
const mongoose = require('mongoose');
const { asyncHandler } = require('../middleware/errorHandler');

const router = express.Router();

// GET /api/health
router.get('/',
  asyncHandler(async (req, res) => {
    const health = {
      status: 'OK',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      environment: process.env.NODE_ENV || 'development',
      database: {
        status: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
        name: mongoose.connection.name
      },
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024 * 100) / 100,
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024 * 100) / 100
      },
      version: '1.0.0'
    };

    // Check database connectivity
    if (mongoose.connection.readyState !== 1) {
      health.status = 'ERROR';
      return res.status(503).json({
        success: false,
        error: 'Database connection failed'
      });
    }

    res.status(200).json({
      success: true,
      data: health
    });
  })
);

// GET /api/health/detailed
router.get('/detailed',
  asyncHandler(async (req, res) => {
    const detailed = {
      status: 'OK',
      timestamp: new Date().toISOString(),
      services: {
        api: {
          status: 'OK',
          uptime: process.uptime(),
          memory: process.memoryUsage(),
          cpu: process.cpuUsage()
        },
        database: {
          status: mongoose.connection.readyState === 1 ? 'Connected' : 'Disconnected',
          host: mongoose.connection.host,
          port: mongoose.connection.port,
          name: mongoose.connection.name,
          readyState: mongoose.connection.readyState
        }
      },
      environment: {
        nodeVersion: process.version,
        platform: process.platform,
        arch: process.arch,
        env: process.env.NODE_ENV || 'development'
      }
    };

    // Overall health check
    const isHealthy = mongoose.connection.readyState === 1;
    
    if (!isHealthy) {
      detailed.status = 'ERROR';
      detailed.services.database.status = 'ERROR';
    }

    const statusCode = isHealthy ? 200 : 503;

    res.status(statusCode).json({
      success: isHealthy,
      data: detailed
    });
  })
);

module.exports = router; 