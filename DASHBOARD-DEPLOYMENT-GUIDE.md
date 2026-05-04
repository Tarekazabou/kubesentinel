# Dashboard Deployment Troubleshooting Guide

## Issue: Dashboard Not Loading Data from Forensic Vault

### What Was Fixed

The dashboard had issues loading data from the forensic vault when deployed. The following improvements have been made:

#### 1. **JavaScript API Endpoint Resolution** (dashboard/index.html)
**Problem**: The API base URL logic was broken for HTTP deployment:
```javascript
// OLD CODE (broken)
const API_BASE_URL = window.location.protocol === 'file:' ? 'http://localhost:5000' : '';
// This resulted in API_BASE_URL = '' when deployed via HTTP, breaking all API calls
```

**Fixed**: Now correctly determines the API endpoint:
```javascript
// NEW CODE (fixed)
const API_BASE_URL = (() => {
    if (window.location.protocol === 'file:') {
        // Local file:// development
        return 'http://localhost:5000';
    }
    // Deployed via HTTP/HTTPS - use current origin
    return window.location.origin;
})();
```

#### 2. **Better Error Logging in Dashboard**
Added detailed console logging to help debug issues:
- Logs API base URL on page load
- Logs API endpoint being called
- Logs error details if data fetch fails
- Shows error message in UI

#### 3. **Improved Flask Backend Logging** (ai-module/server.py)
Added detailed logging in the `/api/incidents` endpoint:
- Logs which forensics paths are being checked
- Reports if forensics directory exists
- Shows number of incident files found

#### 4. **Static File Serving** (ai-module/server.py)
Configured Flask to properly serve static dashboard files:
- Added static folder configuration
- Added catch-all route for static assets
- Ensures all dashboard assets load correctly

#### 5. **Diagnostic Endpoint** (ai-module/server.py)
Added `/api/diagnostics` endpoint to help debug deployment issues:
```bash
curl http://localhost:5000/api/diagnostics
```

## How to Verify the Fix

### Step 1: Check Browser Console
1. Open the dashboard: `http://your-deployment:5000/`
2. Open browser Developer Tools (F12)
3. Check Console tab for logs like:
   ```
   [Dashboard] API Base URL: http://your-deployment:5000
   [Dashboard] Fetching from: http://your-deployment:5000/api/incidents
   [Dashboard] Received incidents: 5 total
   ```

### Step 2: Run Diagnostics
```bash
# From your terminal, check the diagnostic endpoint
curl http://your-deployment:5000/api/diagnostics

# Expected response shows:
# - Dashboard directory path and existence
# - Forensics paths checked and files found
# - CORS configuration
# - Model status
```

### Step 3: Check Server Logs
Look for log messages like:
```
INFO - Checking for forensics at: /app/forensics (exists: True)
INFO - Found 5 incident JSON files in /app/forensics
```

## Deployment Checklist

### Docker Compose Deployment
```bash
# 1. Ensure forensics directory exists
mkdir -p forensics/

# 2. Build and run
docker-compose up --build

# 3. Access dashboard
# http://localhost:5000
```

### Kubernetes Deployment
```bash
# 1. Apply the deployment
kubectl apply -f deploy/kubesentinel-sidecar.yaml

# 2. Port forward to test
kubectl port-forward -n kubesentinel svc/kubesentinel-service 5000:5000

# 3. Access dashboard
# http://localhost:5000

# 4. Check logs
kubectl logs -n kubesentinel deployment/kubesentinel -c ai-module
```

## Common Issues & Solutions

### Issue: Dashboard loads but no data shown
**Symptoms**: Dashboard appears, but "Loading real incidents..." doesn't change
**Solution**: 
1. Check console (F12 > Console tab) for error messages
2. Run `/api/diagnostics` to see where it's looking for forensics files
3. Verify forensics directory is mounted correctly in your deployment

### Issue: 404 Not Found for API endpoints
**Symptoms**: "Failed to load data: API returned 404"
**Solution**:
1. Verify the Flask app is running on the correct port
2. Check that API_BASE_URL is set correctly (see console logs)
3. If using port forwarding, ensure the port is exposed correctly

### Issue: CORS Errors
**Symptoms**: "Access to XMLHttpRequest blocked by CORS policy"
**Solution**:
1. The Flask app already has CORS enabled
2. If behind a reverse proxy, ensure it forwards Origin headers correctly
3. Check CORS_ALLOWED_ORIGINS environment variable

### Issue: Forensics directory not found
**Symptoms**: "Forensics folder not found" in error response
**Solution**:
1. The app looks in these locations (in order):
   - `/app/forensics` (container mounted path)
   - `../forensics` (local dev path)
2. Ensure the forensics directory is created/mounted at deployment
3. Check logs to see which paths were checked

## Environment Variables

```bash
# Enable/disable Gemini enrichment
ENRICH_WITH_GEMINI=true

# Set CORS allowed origins (comma-separated)
CORS_ALLOWED_ORIGINS=http://localhost:5000,http://127.0.0.1:5000

# Gemini API rate limit (calls per minute)
GEMINI_RATE_LIMIT_PER_MINUTE=25

# Model warmup threshold
WARMUP_THRESHOLD=50
```

## API Endpoints Reference

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/` | GET | Serve dashboard HTML |
| `/api/incidents` | GET | Get all incidents from forensics vault |
| `/api/diagnostics` | GET | Get deployment diagnostics |
| `/health` | GET | Health check |
| `/warmup/status` | GET | Check model warmup status |
| `/predict` | POST | Predict anomaly (requires auth token) |
| `/train` | POST | Train model (requires auth token) |

## Testing Locally

```bash
# 1. Install dependencies
pip install -r ai-module/requirements.txt

# 2. Create sample data
mkdir -p forensics
# Place sample incident JSON files in forensics/

# 3. Run the Flask app
cd ai-module
python server.py

# 4. Access dashboard
# http://localhost:5000
```

## Debugging Tips

1. **Check Dashboard Logs**: Open browser F12 > Console to see detailed logs
2. **Check Backend Logs**: Monitor docker logs or kubernetes logs for API errors
3. **Test API Directly**: Use curl or Postman to test `/api/incidents` endpoint
4. **Run Diagnostics**: Use `/api/diagnostics` endpoint to verify configuration
5. **Check Forensics Directory**: Verify files exist and are readable by the container

## Next Steps

If issues persist:
1. Collect logs from both dashboard console and backend
2. Check the diagnostics endpoint response
3. Verify forensics directory has incident JSON files
4. Ensure CORS is not blocking requests
5. Check network in browser DevTools (F12 > Network tab)
