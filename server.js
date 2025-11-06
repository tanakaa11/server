const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const crypto = require('crypto');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { body, param, validationResult } = require('express-validator');
const config = require('./config');

const app = express();
const PORT = config.server.port;
const NODE_ENV = config.server.nodeEnv;

// Security Middleware
const helmetConfig = {
    contentSecurityPolicy: NODE_ENV === 'production' ? {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
            fontSrc: ["'self'", "https://fonts.gstatic.com"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
            connectSrc: ["'self'"],
            frameAncestors: ["'none'"],
        }
    } : false,
    crossOriginEmbedderPolicy: false,
    hsts: {
        maxAge: 31536000, // 1 year
        includeSubDomains: true,
        preload: true
    },
    xssFilter: true,
    noSniff: true,
    frameguard: { action: 'deny' },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
};

app.use(helmet(helmetConfig));

// Enable CORS for all origins and handle preflight
app.use(cors());
app.options('*', cors());

// HTTPS Enforcement in Production
if (NODE_ENV === 'production') {
    app.use((req, res, next) => {
        // Check if request is secure (HTTPS)
        if (req.header('x-forwarded-proto') !== 'https' && 
            req.protocol !== 'https' && 
            req.get('host') && !req.get('host').includes('localhost')) {
            return res.redirect(`https://${req.get('host')}${req.url}`);
        }
        next();
    });
    
    // Trust proxy (for platforms like Heroku, Railway, etc.)
    app.set('trust proxy', 1);
}

// Import CORS config
//const corsConfig = require('../cors-config');

// Apply CORS middleware
//app.use(cors(corsConfig));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Rate Limiting - Stricter in production
const limiter = rateLimit({
    windowMs: config.rateLimit.windowMs,
    max: NODE_ENV === 'production' 
        ? Math.min(config.rateLimit.maxRequests, 150) // Cap at 150 in production
        : config.rateLimit.maxRequests,
    message: {
        error: 'Too many requests',
        message: 'Rate limit exceeded. Please try again later.',
        retryAfter: Math.ceil(config.rateLimit.windowMs / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false,
    skip: (req) => {
        // Skip rate limiting for health checks
        return req.path === '/api/health';
    }
});

// Stricter rate limit for uploads
const uploadLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: NODE_ENV === 'production' ? 15 : 20, // Stricter in production
    message: {
        error: 'Too many uploads',
        message: 'Upload rate limit exceeded. Please try again later.',
        retryAfter: 3600
    },
    standardHeaders: true,
    legacyHeaders: false,
});

app.use('/api/', limiter);
app.use('/api/upload', uploadLimiter);

// Request logging
if (NODE_ENV === 'development') {
    app.use((req, res, next) => {
        console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
        next();
    });
} else {
    // Production: Log only errors and important events
    app.use((req, res, next) => {
        // Log security-related requests
        if (req.path.includes('/api/upload') || req.path.includes('/api/room')) {
            console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} - IP: ${req.ip}`);
        }
        next();
    });
}

// Create uploads directory if it doesn't exist
const uploadsDir = path.join(__dirname, config.uploads.directory);
if (!fs.existsSync(uploadsDir)) {
    fs.mkdirSync(uploadsDir, { recursive: true });
}

// File validation
function validateFileType(file) {
    const allowedTypes = config.security.allowedFileTypes;
    const allowedExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx', 
                              '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.zip', '.rar'];
    
    // Check MIME type
    if (allowedTypes.includes(file.mimetype)) {
        return true;
    }
    
    // Check file extension as fallback
    const ext = path.extname(file.originalname).toLowerCase();
    return allowedExtensions.includes(ext);
}

// Sanitize filename
function sanitizeFilename(filename) {
    return filename
        .replace(/[^a-zA-Z0-9._-]/g, '_')
        .replace(/_{2,}/g, '_')
        .substring(0, 255); // Max filename length
}

// Upload storage configuration
const uploadStorage = multer.diskStorage({
    destination: (req, file, cb) => {
        const tempDir = path.join(uploadsDir, 'temp');
        if (!fs.existsSync(tempDir)) {
            fs.mkdirSync(tempDir, { recursive: true });
        }
        cb(null, tempDir);
    },
    filename: (req, file, cb) => {
        // Validate file type
        if (!validateFileType(file)) {
            return cb(new Error(`File type not allowed: ${file.mimetype}`));
        }
        
        // Sanitize and generate filename
        const sanitized = sanitizeFilename(file.originalname);
        const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
        const ext = path.extname(sanitized);
        const baseName = path.basename(sanitized, ext);
        cb(null, `${uniqueSuffix}-${baseName}${ext}`);
    }
});

const uploadMiddleware = multer({ 
    storage: uploadStorage,
    limits: {
        fileSize: config.security.maxFileSize,
        files: config.security.maxFilesPerUpload
    },
    fileFilter: (req, file, cb) => {
        if (validateFileType(file)) {
            cb(null, true);
        } else {
            cb(new Error(`File type ${file.mimetype} is not allowed`), false);
        }
    }
}).array('files');

// Store file metadata and deletion timers
const fileStore = new Map();

// Generate unique code
function generateCode() {
    return crypto.randomBytes(8).toString('hex');
}

// Generate creator token
function generateCreatorToken() {
    return crypto.randomBytes(16).toString('hex');
}

// Schedule file deletion with enhanced cleanup
function scheduleDeletion(code, delay = config.room.expiryHours * 60 * 60 * 1000) {
    const codeDir = path.join(uploadsDir, code);
    const now = Date.now();
    const expiresAt = now + delay;
    
    const deleteFiles = () => {
        console.log(`Deleting files for room: ${code}`);
        deleteFileSafely(codeDir);
        fileStore.delete(code);
    };
    
    // Clear any existing timer
    const existing = fileStore.get(code);
    if (existing && existing.deleteTimer) {
        clearTimeout(existing.deleteTimer);
    }
    
    // Set new timer
    const timer = setTimeout(deleteFiles, delay);
    
    // Update file store with new expiration
    const data = fileStore.get(code) || {
        files: [],
        downloadedCount: 0,
        createdAt: now
    };
    
    data.deleteTimer = timer;
    data.expiresAt = expiresAt;
    fileStore.set(code, data);
}

// Validation error handler
const handleValidationErrors = (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
        return res.status(400).json({ 
            error: 'Validation failed', 
            errors: errors.array() 
        });
    }
    next();
};

// Create room endpoint
app.post('/api/room/create', 
    rateLimit({
        windowMs: 60 * 60 * 1000, // 1 hour
        max: 50, // 50 rooms per hour per IP
        message: 'Too many room creation requests.'
    }),
    (req, res) => {
        try {
            const code = generateCode();
            const creatorToken = generateCreatorToken();
            const codeDir = path.join(uploadsDir, code);
            
            if (!fs.existsSync(codeDir)) {
                fs.mkdirSync(codeDir, { recursive: true });
            }
            
            fileStore.set(code, {
                files: [],
                deleteTimer: null,
                downloadedCount: 0,
                totalFiles: 0,
                creatorToken: creatorToken,
                createdAt: Date.now()
            });
            
            scheduleDeletion(code, config.room.expiryHours * 60 * 60 * 1000);
            
            res.json({
                code: code,
                creatorToken: creatorToken,
                message: 'Room created successfully'
            });
        } catch (error) {
            console.error('Create room error:', error.message);
            res.status(500).json({ error: 'Failed to create room', message: error.message });
        }
    }
);

// Upload endpoint
app.post('/api/upload', 
    uploadMiddleware,
    (req, res) => {
        try {
            const roomCode = req.query.roomCode || (req.body && req.body.roomCode ? req.body.roomCode : null);
            
            // Validate room code format
            if (!roomCode || typeof roomCode !== 'string' || !/^[a-f0-9]{16}$/.test(roomCode)) {
                // Clean up temp files
                if (req.files && Array.isArray(req.files) && req.files.length > 0) {
                    req.files.forEach(file => {
                        try {
                            if (fs.existsSync(file.path)) {
                                fs.unlinkSync(file.path);
                            }
                        } catch (e) {}
                    });
                }
                return res.status(400).json({ error: 'Invalid room code format' });
            }
            
            const uploadedFiles = req.files || [];
            
            if (!uploadedFiles || uploadedFiles.length === 0) {
                return res.status(400).json({ error: 'No files uploaded' });
            }
            
            // Check if room exists
            const roomData = fileStore.get(roomCode);
            if (!roomData) {
                // Clean up temp files
                uploadedFiles.forEach(file => {
                    try {
                        if (fs.existsSync(file.path)) {
                            fs.unlinkSync(file.path);
                        }
                    } catch (e) {}
                });
                return res.status(404).json({ error: 'Room not found. Please create a room first.' });
            }
            
            const codeDir = path.join(uploadsDir, roomCode);
            if (!fs.existsSync(codeDir)) {
                fs.mkdirSync(codeDir, { recursive: true });
            }
            
            // Move files from temp directory to room directory
            const newFiles = uploadedFiles.map(file => {
                const oldPath = file.path;
                const newFilename = file.filename;
                const newPath = path.join(codeDir, newFilename);
                
                if (fs.existsSync(oldPath)) {
                    fs.renameSync(oldPath, newPath);
                }
                
                return {
                    filename: newFilename,
                    originalName: file.originalname,
                    size: file.size,
                    mimetype: file.mimetype
                };
            });
            
            // Add new files to existing files
            const allFiles = [...(roomData.files || []), ...newFiles];
            
            // Update room data
            roomData.files = allFiles;
            roomData.totalFiles = allFiles.length;
            fileStore.set(roomCode, roomData);
            
            res.json({ 
                code: roomCode,
                files: allFiles,
                message: 'Files uploaded successfully'
            });
        } catch (error) {
            console.error('Upload error:', error.message);
            res.status(500).json({ error: 'Upload failed', message: error.message });
        }
    }
);

// Get files list endpoint
app.get('/api/files/:code',
    param('code').isHexadecimal().isLength({ min: 16, max: 16 }),
    handleValidationErrors,
    (req, res) => {
        try {
            const code = req.params.code;
            const codeDir = path.join(uploadsDir, code);
            
            if (!fs.existsSync(codeDir)) {
                return res.status(404).json({ error: 'Files not found or expired' });
            }
            
            const fileData = fileStore.get(code);
            if (!fileData) {
                // Try to rebuild from disk
                try {
                    const filesOnDisk = fs.readdirSync(codeDir);
                    const rebuiltFiles = filesOnDisk.map(filename => {
                        const filePath = path.join(codeDir, filename);
                        const stats = fs.statSync(filePath);
                        const originalNameMatch = filename.match(/^\d+-\d+-(.+)$/);
                        const originalName = originalNameMatch ? originalNameMatch[1] : filename;
                        
                        return {
                            filename: filename,
                            originalName: originalName,
                            size: stats.size,
                            mimetype: 'application/octet-stream'
                        };
                    });
                    
                    fileStore.set(code, {
                        files: rebuiltFiles,
                        deleteTimer: null,
                        downloadedCount: 0,
                        totalFiles: rebuiltFiles.length
                    });
                    
                    return res.json({
                        code: code,
                        files: rebuiltFiles
                    });
                } catch (rebuildError) {
                    return res.status(404).json({ error: 'Files not found or expired' });
                }
            }
            
            res.json({
                code: code,
                files: fileData.files || []
            });
        } catch (error) {
            console.error('Get files error:', error.message);
            res.status(500).json({ error: 'Failed to retrieve files', message: error.message });
        }
    }
);

// Download endpoint
app.get('/api/download/:code/:filename',
    param('code').isHexadecimal().isLength({ min: 16, max: 16 }),
    handleValidationErrors,
    (req, res) => {
        try {
            const code = req.params.code;
            const filename = sanitizeFilename(req.params.filename);
            const codeDir = path.join(uploadsDir, code);
            const filePath = path.join(codeDir, filename);
            
            // Security: Prevent directory traversal
            if (!filePath.startsWith(codeDir)) {
                return res.status(400).json({ error: 'Invalid file path' });
            }
            
            if (!fs.existsSync(filePath)) {
                return res.status(404).json({ error: 'File not found' });
            }
            
            const fileData = fileStore.get(code);
            if (!fileData) {
                return res.status(404).json({ error: 'File metadata not found' });
            }
            
            const fileInfo = fileData.files.find(f => f.filename === filename);
            if (!fileInfo) {
                return res.status(404).json({ error: 'File info not found' });
            }
            
            res.download(filePath, fileInfo.originalName, (err) => {
                if (err) {
                    console.error('Download error:', err.message);
                    if (!res.headersSent) {
                        res.status(500).json({ error: 'Download failed', message: err.message });
                    }
                }
            });
        } catch (error) {
            console.error('Download error:', error.message);
            res.status(500).json({ error: 'Download failed', message: error.message });
        }
    }
);

// Mark as downloaded endpoint
app.post('/api/downloaded/:code',
    param('code').isHexadecimal().isLength({ min: 16, max: 16 }),
    handleValidationErrors,
    (req, res) => {
        try {
            const code = req.params.code;
            const fileData = fileStore.get(code);
            
            if (!fileData) {
                return res.status(404).json({ error: 'Files not found' });
            }
            
            fileData.downloadedCount = (fileData.downloadedCount || 0) + 1;
            fileStore.set(code, fileData);
            
            // If all files have been downloaded, schedule deletion
            if (fileData.downloadedCount >= fileData.totalFiles && fileData.totalFiles > 0) {
                scheduleDeletion(code, config.room.postDownloadDelayMinutes * 60 * 1000);
            }
            
            res.json({ message: 'Download registered' });
        } catch (error) {
            console.error('Downloaded endpoint error:', error.message);
            res.status(500).json({ error: 'Failed to register download', message: error.message });
        }
    }
);

// Delete room endpoint
app.delete('/api/room/:code',
    param('code').isHexadecimal().isLength({ min: 16, max: 16 }),
    body('creatorToken').optional().isHexadecimal(),
    handleValidationErrors,
    (req, res) => {
        try {
            const code = req.params.code;
            const creatorToken = req.body.creatorToken || req.query.creatorToken;
            
            const codeDir = path.join(uploadsDir, code);
            const fileData = fileStore.get(code);
            
            if (!fileData) {
                return res.status(404).json({ error: 'Room not found or already deleted' });
            }
            
            // Verify creator token
            if (!creatorToken || fileData.creatorToken !== creatorToken) {
                return res.status(403).json({ error: 'Only the room creator can delete the room' });
            }
            
            // Clear deletion timer
            if (fileData.deleteTimer) {
                clearTimeout(fileData.deleteTimer);
            }
            
            // Delete files immediately
            if (fs.existsSync(codeDir)) {
                fs.rmSync(codeDir, { recursive: true, force: true });
            }
            fileStore.delete(code);
            
            res.json({ message: 'Room deleted successfully' });
        } catch (error) {
            console.error('Delete room error:', error.message);
            res.status(500).json({ error: 'Failed to delete room', message: error.message });
        }
    }
);

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        uptime: process.uptime()
    });
});

// Error handling middleware
app.use((err, req, res, next) => {
    // Log full error details in development
    if (NODE_ENV === 'development') {
        console.error('Error:', err.message);
        console.error('Stack:', err.stack);
    } else {
        // Production: Log but don't expose details
        console.error(`[ERROR] ${req.method} ${req.path}: ${err.message}`);
    }
    
    if (err instanceof multer.MulterError) {
        if (err.code === 'LIMIT_FILE_SIZE') {
            return res.status(400).json({ error: 'File too large' });
        }
        if (err.code === 'LIMIT_FILE_COUNT') {
            return res.status(400).json({ error: 'Too many files' });
        }
        return res.status(400).json({ error: 'Upload error' });
    }
    
    // // CORS errors
    // if (err.message && err.message.includes('CORS')) {
    //     return res.status(403).json({ error: 'CORS policy violation' });
    // }
    
    // Generic error response (don't leak internal details in production)
    const statusCode = err.status || 500;
    const errorMessage = NODE_ENV === 'development' 
        ? err.message 
        : statusCode === 500 
            ? 'Internal server error' 
            : err.message;
    
    res.status(statusCode).json({ 
        error: errorMessage,
        ...(NODE_ENV === 'development' && { stack: err.stack })
    });
});

// 404 handler
app.use((req, res) => {
    res.status(404).json({ error: 'Route not found' });
});

// Cleanup function for expired files and temporary files
function cleanupExpiredFiles() {
    const now = Date.now();
    const tempDir = path.join(uploadsDir, 'temp');
    
    // Clean up expired rooms
    fileStore.forEach((data, code) => {
        if (data.expiresAt && data.expiresAt <= now) {
            const codeDir = path.join(uploadsDir, code);
            try {
                if (fs.existsSync(codeDir)) {
                    fs.rmSync(codeDir, { recursive: true, force: true });
                    console.log(`Cleaned up expired room: ${code}`);
                }
                fileStore.delete(code);
            } catch (error) {
                console.error(`Error cleaning up room ${code}:`, error.message);
            }
        }
    });
    
    // Clean up old temporary files (older than 1 hour)
    try {
        if (fs.existsSync(tempDir)) {
            const files = fs.readdirSync(tempDir);
            const now = Date.now();
            const oneHour = 60 * 60 * 1000;
            
            files.forEach(file => {
                const filePath = path.join(tempDir, file);
                try {
                    const stats = fs.statSync(filePath);
                    // Delete temp files older than 1 hour
                    if (now - stats.mtime.getTime() > oneHour) {
                        fs.unlinkSync(filePath);
                        console.log(`Cleaned up temporary file: ${file}`);
                    }
                } catch (error) {
                    console.error(`Error cleaning up temp file ${file}:`, error.message);
                }
            });
        }
    } catch (error) {
        console.error('Error during temp file cleanup:', error.message);
    }
}

// Enhanced file deletion function
function deleteFileSafely(filePath) {
    try {
        if (fs.existsSync(filePath)) {
            // If it's a directory, remove recursively
            if (fs.lstatSync(filePath).isDirectory()) {
                fs.rmSync(filePath, { recursive: true, force: true });
            } else {
                fs.unlinkSync(filePath);
            }
            return true;
        }
    } catch (error) {
        console.error(`Error deleting ${filePath}:`, error.message);
    }
    return false;
}

// Run cleanup every 15 minutes for more frequent cleanup
setInterval(cleanupExpiredFiles, 15 * 60 * 1000);

// Initial cleanup on startup
cleanupExpiredFiles();

// Handle process termination
process.on('SIGINT', () => {
    console.log('Shutting down server...');
    // Clean up all files on shutdown
    fileStore.forEach((_, code) => {
        const codeDir = path.join(uploadsDir, code);
        deleteFileSafely(codeDir);
    });
    // Clean up temp directory
    const tempDir = path.join(uploadsDir, 'temp');
    deleteFileSafely(tempDir);
    process.exit(0);
});

// HTTPS/SSL Configuration (for self-hosted)
let server;
if (NODE_ENV === 'production' && process.env.SSL_CERT_PATH && process.env.SSL_KEY_PATH) {
    const https = require('https');
    try {
        const cert = fs.readFileSync(process.env.SSL_CERT_PATH);
        const key = fs.readFileSync(process.env.SSL_KEY_PATH);
        const options = {
            key: key,
            cert: cert
        };
        server = https.createServer(options, app);
        console.log('🔒 HTTPS enabled with custom SSL certificates');
    } catch (error) {
        console.error('⚠️  SSL certificate error, falling back to HTTP:', error.message);
        server = app;
    }
} else {
    server = app;
}

// Security warnings
if (NODE_ENV === 'production') {
    if (config.security.allowedOrigins.length === 0 || config.security.allowedOrigins.includes('*')) {
        console.warn('⚠️  WARNING: CORS is open to all origins! Set ALLOWED_ORIGINS in .env');
    }
    if (!process.env.ALLOWED_ORIGINS) {
        console.warn('⚠️  WARNING: ALLOWED_ORIGINS not set in environment variables');
    }
}

server.listen(PORT, () => {
    console.log(`🚀 AetherSend backend server running on port ${PORT}`);
    console.log(`📁 Upload directory: ${uploadsDir}`);
    console.log(`🌐 Environment: ${NODE_ENV}`);
    console.log(`🔒 Security: ${NODE_ENV === 'production' ? 'PRODUCTION MODE' : 'DEVELOPMENT MODE'}`);
    console.log(`✅ Server ready`);
    
    if (NODE_ENV === 'production') {
        console.log('📋 Security Checklist:');
        console.log(`   ✓ Environment: ${NODE_ENV}`);
        console.log(`   ✓ CORS Origins: ${config.security.allowedOrigins.length > 0 ? config.security.allowedOrigins.join(', ') : 'NOT SET (⚠️)'}`);
        console.log(`   ✓ Rate Limiting: Enabled`);
        console.log(`   ✓ File Validation: Enabled`);
        console.log(`   ✓ HTTPS: ${process.env.SSL_CERT_PATH ? 'Custom SSL' : 'Platform-managed (Heroku/Railway/etc)'}`);
    }
});

// Graceful shutdown
process.on('SIGTERM', () => {
    console.log('SIGTERM received, shutting down gracefully...');
    process.exit(0);
});

process.on('SIGINT', () => {
    console.log('SIGINT received, shutting down gracefully...');
    process.exit(0);
});
