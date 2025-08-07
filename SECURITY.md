# Security Guide for PII Scanner Web App

## 🔒 Security Features Implemented

### 1. Admin Authentication
- **Basic HTTP Authentication** for admin dashboard
- **Environment variables** for credentials
- **Secure credential comparison** using `secrets.compare_digest()`

### 2. File Upload Security
- **File size limits**: 10MB maximum
- **File type validation**: Only allowed extensions
- **Duplicate detection**: MD5 hash checking
- **Temporary file handling**: Automatic cleanup

### 3. Data Protection
- **No PII storage**: Only metadata and hashes stored
- **IP address logging**: For abuse prevention
- **User agent tracking**: For analytics only

## 🚨 Security Checklist

### Before Deployment:
- [ ] Change default admin credentials
- [ ] Set environment variables for production
- [ ] Configure HTTPS (automatic on Vercel/Railway)
- [ ] Review file upload limits
- [ ] Test authentication

### Production Security:
- [ ] Use strong admin password
- [ ] Regularly rotate credentials
- [ ] Monitor access logs
- [ ] Backup database regularly
- [ ] Keep dependencies updated

## 🔧 Configuration

### Environment Variables:
```bash
# Set these in your deployment platform
ADMIN_USERNAME=your-admin-username
ADMIN_PASSWORD=your-secure-password
```

### Vercel Configuration:
```json
{
  "env": {
    "ADMIN_USERNAME": "your-admin-username",
    "ADMIN_PASSWORD": "your-secure-password"
  }
}
```

### Railway Configuration:
```bash
# Set in Railway dashboard
ADMIN_USERNAME=your-admin-username
ADMIN_PASSWORD=your-secure-password
```

## 🛡️ Additional Security Recommendations

### 1. Rate Limiting (Future Enhancement)
```python
# Add rate limiting middleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
app.state.limiter = limiter

@app.post("/upload")
@limiter.limit("10/minute")  # 10 uploads per minute per IP
async def upload_file(request: Request, file: UploadFile = File(...)):
    # ... existing code
```

### 2. File Content Validation
```python
# Add file content validation
def validate_file_content(content: bytes, filename: str) -> bool:
    # Check for malicious content
    # Validate file headers
    # Scan for executable content
    pass
```

### 3. Database Encryption
```python
# Use encrypted database
import sqlcipher3
conn = sqlcipher3.connect('pii_scanner.db')
conn.execute("PRAGMA key='your-encryption-key'")
```

### 4. API Key Authentication (Alternative)
```python
# Use API keys instead of basic auth
from fastapi import Header

async def verify_api_key(x_api_key: str = Header(...)):
    if x_api_key != "your-api-key":
        raise HTTPException(status_code=401, detail="Invalid API key")
```

## 🚨 Security Warnings

### Current Limitations:
1. **Basic authentication** - Consider stronger auth for production
2. **No rate limiting** - Vulnerable to abuse
3. **SQLite database** - Not suitable for high concurrency
4. **No file content scanning** - Could upload malicious files

### Recommended Upgrades:
1. **JWT authentication** for better security
2. **Redis rate limiting** for abuse prevention
3. **PostgreSQL database** for production scale
4. **File content scanning** for malware detection
5. **CORS configuration** for domain restrictions

## 🔍 Monitoring

### What to Monitor:
- Failed authentication attempts
- Large file uploads
- Unusual traffic patterns
- Database access patterns
- Error rates

### Log Analysis:
```bash
# Check for failed logins
grep "401" logs/access.log

# Monitor file uploads
grep "POST /upload" logs/access.log

# Check for large files
grep "413" logs/access.log
```

## 📞 Security Contact

If you discover a security vulnerability:
1. **Do not** disclose publicly
2. **Contact** the development team
3. **Provide** detailed reproduction steps
4. **Wait** for acknowledgment and fix

## 🔄 Security Updates

- **Regular dependency updates**
- **Security patch monitoring**
- **Credential rotation**
- **Access log review**
- **Backup verification** 