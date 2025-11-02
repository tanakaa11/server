# Security Features

## Implemented Security Measures

### 1. **Helmet.js** - HTTP Security Headers
- Sets various HTTP headers to help secure the app
- Prevents XSS attacks, clickjacking, and other common vulnerabilities

### 2. **CORS Configuration**
- Whitelist-based origin checking
- Only allows requests from configured origins
- Prevents unauthorized cross-origin requests

### 3. **Rate Limiting**
- General API: 100 requests per 15 minutes per IP
- Upload endpoint: 20 uploads per hour per IP
- Room creation: 50 rooms per hour per IP
- Prevents abuse and DoS attacks

### 4. **Input Validation**
- Express-validator for route parameters
- Hexadecimal validation for room codes
- Filename sanitization to prevent path traversal
- File type validation

### 5. **File Upload Security**
- File type whitelist (MIME type checking)
- File size limits (configurable, default 100MB)
- Maximum files per upload (default 50)
- Filename sanitization
- Directory traversal prevention

### 6. **Authentication/Authorization**
- Creator token system for room deletion
- Room code validation (hexadecimal, fixed length)
- Token verification before destructive operations

### 7. **Error Handling**
- Generic error messages in production
- Detailed logging (development only)
- No sensitive information in error responses

### 8. **Automatic Cleanup**
- Files auto-delete after expiry
- Prevents storage abuse
- Regular cleanup of expired entries

## Configuration

All security settings can be configured via environment variables (see `.env.example`).

## Best Practices

1. **Never commit `.env` files** - Contains sensitive configuration
2. **Use HTTPS in production** - Configure SSL/TLS certificates
3. **Monitor logs** - Watch for suspicious activity
4. **Keep dependencies updated** - Run `npm audit` regularly
5. **Set proper CORS origins** - Only allow trusted domains
6. **Configure rate limits appropriately** - Adjust based on your needs
7. **Use environment-specific configs** - Different settings for dev/prod

## Additional Security Recommendations

For production deployment, consider:

- **WAF (Web Application Firewall)** - CloudFlare, AWS WAF, etc.
- **DDoS Protection** - CloudFlare, AWS Shield, etc.
- **File Virus Scanning** - ClamAV, VirusTotal API
- **Monitoring** - Sentry, LogRocket, DataDog
- **Backup Strategy** - Regular backups of important data
- **SSL/TLS** - Always use HTTPS
- **Container Security** - If using Docker, scan images
- **Database** - If adding a database, use prepared statements

