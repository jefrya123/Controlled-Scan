# PII Scanner Web App

A simple web interface for testing the PII detection system.

## Quick Start

### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Install spaCy model
python -m spacy download en_core_web_lg

# Run the app
python app.py

# Open http://localhost:8000
```

### Deploy to Vercel (Recommended)

1. **Install Vercel CLI**
```bash
npm install -g vercel
```

2. **Create vercel.json**
```json
{
  "version": 2,
  "builds": [
    {
      "src": "app.py",
      "use": "@vercel/python"
    }
  ],
  "routes": [
    {
      "src": "/(.*)",
      "dest": "app.py"
    }
  ]
}
```

3. **Deploy**
```bash
vercel --prod
```

### Deploy to Railway

1. **Create Procfile**
```
web: uvicorn app:app --host 0.0.0.0 --port $PORT
```

2. **Connect GitHub repo to Railway**
3. **Auto-deploys on push**

### Deploy to Heroku

1. **Create Procfile**
```
web: uvicorn app:app --host 0.0.0.0 --port $PORT
```

2. **Deploy**
```bash
heroku create your-pii-scanner
git push heroku main
```

## Features

- 📁 File upload (drag & drop)
- 🔍 PII detection with Presidio
- 📊 Results categorized by controlled/non-controlled
- 💬 Feedback collection
- 📈 Basic statistics

## File Support

- Text files (.txt)
- CSV files (.csv)
- PDF files (.pdf)
- Word documents (.docx)
- Excel files (.xlsx)
- JSON files (.json)
- XML files (.xml)

## API Endpoints

- `GET /` - Main web interface
- `POST /upload` - Upload and scan files
- `POST /feedback` - Submit user feedback
- `GET /stats` - Get system statistics 