require('dotenv').config();

module.exports = {
    server: {
        port: process.env.PORT || 3000 || 8080,
        nodeEnv: process.env.NODE_ENV || 'development'
    },
    security: {
        allowedOrigins: process.env.ALLOWED_ORIGINS 
            ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
            : process.env.NODE_ENV === 'production' 
                ? ['https://server-2fei5ybnh-tanakaa11s-projects.vercel.app', 'https://aether-send.vercel.app']
                : ['http://localhost:8000', 'http://localhost:3000', 'http://127.0.0.1:5500'],
        maxFileSize: parseInt(process.env.MAX_FILE_SIZE) || 100 * 1024 * 1024, // 100MB
        maxFilesPerUpload: parseInt(process.env.MAX_FILES_PER_UPLOAD) || 50,
        allowedFileTypes: [
            // Documents
            'application/pdf',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/vnd.ms-powerpoint',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            // Images
            'image/jpeg',
            'image/png',
            'image/gif',
            'image/webp',
            'image/svg+xml',
            // Text
            'text/plain',
            'text/csv',
            'text/html',
            // Archives
            'application/zip',
            'application/x-rar-compressed',
            'application/x-tar',
            'application/gzip',
            // Media
            'video/mp4',
            'video/mpeg',
            'audio/mpeg',
            'audio/wav',
            // Generic
            'application/octet-stream'
        ]
    },
    room: {
        expiryHours: parseInt(process.env.ROOM_EXPIRY_HOURS) || 24,
        postDownloadDelayMinutes: 5
    },
    rateLimit: {
        windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
        maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100
    },
    uploads: {
        directory: process.env.UPLOAD_DIR || './uploads'
    }
};

