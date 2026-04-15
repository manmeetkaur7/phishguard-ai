# PhishGuard AI

PhishGuard AI is a phishing and scam detection project with a FastAPI backend and an Expo React Native mobile app.

## Structure

- `backend/` — Python FastAPI backend that analyzes text and URLs for phishing indicators.
- `mobile/` — Expo React Native app for submitting content and reviewing analysis results.

## Setup

### Backend

1. Create and activate a Python virtual environment.
2. Install dependencies.
3. Run the backend:

```powershell
cd backend
python -m venv venv
.\venv\Scripts\Activate
pip install fastapi uvicorn
uvicorn main:app --reload --host 0.0.0.0 --port 8000
```

### Mobile

1. Install npm dependencies.
2. Run the Expo app.

```powershell
cd mobile
npm install
npm run start
```

## Notes

- The mobile app is configured to use a local backend host.
- The backend returns `verdict`, `score`, `confidence`, `attack_type`, and `explanations` for each analysis.

## License

This project is licensed under the MIT License.
