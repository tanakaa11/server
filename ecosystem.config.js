// PM2 Ecosystem Configuration (for process management)
module.exports = {
    apps: [{
        name: 'aethersend-backend',
        script: './server.js',
        instances: 1,
        exec_mode: 'fork',
        env: {
            NODE_ENV: 'development',
            PORT: 3000
        },
        env_production: {
            NODE_ENV: 'production',
            PORT: 3000
        },
        error_file: './logs/err.log',
        out_file: './logs/out.log',
        log_date_format: 'YYYY-MM-DD HH:mm:ss Z',
        merge_logs: true,
        autorestart: true,
        max_memory_restart: '1G',
        watch: false
    }]
};

