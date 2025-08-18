// MongoDB initialization script for SekaiBank
// This script runs when the MongoDB container starts for the first time

print('Starting MongoDB initialization for SekaiBank...');

// Switch to the sekaibank database
db = db.getSiblingDB('sekaibank');

// Create indexes for better performance
print('Creating database indexes...');

// User collection indexes
db.users.createIndex({ "username": 1 }, { unique: true });
db.users.createIndex({ "email": 1 }, { unique: true });
db.users.createIndex({ "accountStatus": 1 });
db.users.createIndex({ "createdAt": 1 });

// Transaction collection indexes
db.transactions.createIndex({ "referenceId": 1 }, { unique: true });
db.transactions.createIndex({ "fromUserId": 1, "createdAt": -1 });
db.transactions.createIndex({ "toUserId": 1, "createdAt": -1 });
db.transactions.createIndex({ "status": 1 });
db.transactions.createIndex({ "createdAt": -1 });

// AuditLog collection indexes
db.auditlogs.createIndex({ "userId": 1, "createdAt": -1 });
db.auditlogs.createIndex({ "action": 1, "createdAt": -1 });
db.auditlogs.createIndex({ "severity": 1, "createdAt": -1 });
db.auditlogs.createIndex({ "createdAt": -1 });
db.auditlogs.createIndex({ "ipAddress": 1 });
db.auditlogs.createIndex({ "success": 1 });

print('Database indexes created successfully.');

// Create users
db.users.insertOne({
    username: "admin",
    email: "admin@sekai.team",
    password: "$2y$12$uxa2EBNi0lzKrWdRaRWlQ.tPELp9xJQ/cj7cempRqbhKx/5SFCgf2", // Admin123#S3k4i
    balance: 1000000000,
    pin: "$2y$12$jHV7IwdMqKvASHJ47hgjp.zS6vTw0RAtXdNkPEsnxLEejdtfPVsyG", // 443123
    pinAttempts: 0,
    pinLockedUntil: null,
    lastLoginAt: new Date(),
    isEmailVerified: true,
    accountStatus: "ACTIVE",
    refreshTokens: [],
    pinVerifiedAt: null,
    pinSessionExpiry: null,
    loginAttempts: 0,
    lockUntil: null,
    createdAt: new Date(),
    updatedAt: new Date()
});

db.users.insertOne({
    username: "nino",
    email: "nino@sekai.team",
    password: "$2y$12$uxa2EBNi0lzKrWdRaRWlQ.tPELp9xJQ/cj7cempRqbhKx/5SFCgf2", // Admin123#S3k4i
    balance: 0,
    pin: "$2y$12$hrqlgbr.DEeity2aF2N2.uXnx5o7g0R/dffGSFDmHlUUWrsv/m5US", // 904712
    pinAttempts: 0,
    pinLockedUntil: null,
    lastLoginAt: new Date(),
    isEmailVerified: true,
    accountStatus: "ACTIVE",
    refreshTokens: [],
    pinVerifiedAt: null,
    pinSessionExpiry: null,
    loginAttempts: 0,
    lockUntil: null,
    createdAt: new Date(),
    updatedAt: new Date()
});

print('MongoDB initialization completed successfully.'); 