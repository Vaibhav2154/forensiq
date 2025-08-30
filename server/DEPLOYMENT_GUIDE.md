# ForensIQ API Deployment Guide

## 🚀 Deploy to Render

### Method 1: Using render.yaml (Recommended)

1. **Push code to GitHub** with the `render.yaml` file
2. **Connect to Render:**
   - Go to [Render Dashboard](https://dashboard.render.com/)
   - Click "New" → "Blueprint"
   - Connect your GitHub repository
   - Select the repository containing your code

3. **Set Environment Variables:**
   ```
   GEMINI_API_KEY=your-gemini-api-key
   AWS_ACCESS_KEY_ID=your-aws-access-key
   AWS_SECRET_ACCESS_KEY=your-aws-secret-key
   AWS_REGION=us-east-1
   LOG_LEVEL=INFO
   ```

### Method 2: Manual Service Creation

1. **Create Web Service:**
   - Go to Render Dashboard
   - Click "New" → "Web Service"
   - Connect GitHub repository

2. **Configure Service:**
   ```
   Name: forensiq-api
   Runtime: Python 3
   Build Command: pip install --upgrade pip && pip install -r requirements.txt
   Start Command: uvicorn main:app --host 0.0.0.0 --port $PORT
   ```

3. **Set Environment Variables** (same as above)

## 🔧 Fixing Port Detection Issues

### Issue: "No open ports detected"

**Cause:** Render cannot detect that your service is listening on a port.

**Solutions:**

1. **Ensure PORT environment variable is used:**
   ```python
   PORT = int(os.getenv("PORT", 8000))
   ```

2. **Use explicit uvicorn command:**
   ```bash
   uvicorn main:app --host 0.0.0.0 --port $PORT
   ```

3. **Add health check endpoint** (already implemented):
   ```
   GET /health
   GET /
   ```

### Troubleshooting Commands

**Check if service is running:**
```bash
curl https://your-app.onrender.com/health
```

**Check logs in Render:**
- Go to your service dashboard
- Click on "Logs" tab
- Look for startup messages

## 📋 Pre-Deployment Checklist

- [ ] All required environment variables set
- [ ] `requirements.txt` is up to date
- [ ] Health check endpoint working locally
- [ ] Database initialization working
- [ ] API keys are valid and have required permissions

## 🐛 Common Issues

### 1. Build Timeout
**Solution:** Use lighter dependencies or increase build timeout in Render settings.

### 2. Memory Issues
**Solution:** 
- Use Render's Starter plan or higher
- Optimize ChromaDB configuration
- Consider lazy loading of large models

### 3. Database Connection Issues
**Solution:**
- Ensure ChromaDB persistence directory is writable
- Check that MITRE ATT&CK data files are accessible

### 4. API Key Issues
**Solution:**
- Verify all API keys are correctly set in environment variables
- Test API keys locally before deployment
- Check API rate limits and quotas

## 🚀 Production Optimization

1. **Use production-ready database:** Consider PostgreSQL with ChromaDB
2. **Add caching:** Implement Redis for frequently accessed data
3. **Monitor performance:** Use Render's built-in monitoring
4. **Scale resources:** Upgrade to higher tier plans for production

## 📞 Support

If deployment issues persist:
1. Check Render logs for specific error messages
2. Verify all environment variables are set correctly
3. Test the application locally with the same configuration
4. Contact Render support with specific error details
