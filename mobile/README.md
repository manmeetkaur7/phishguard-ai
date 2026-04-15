# PhishGuard AI: Scam Analyzer

PhishGuard AI is a full-stack mobile scam detection app that analyzes suspicious emails, URLs, job scams, fake recruiter messages, banking/payment scams, OTP scams, package delivery scams, and suspicious call transcripts.

## Features
- Email scam detection
- URL scam detection
- Job scam detection
- Call transcript analysis
- Risk scoring
- Scam type classification
- Confidence level
- Recommended action
- Scan history

## Tech Stack
- React Native / Expo
- FastAPI
- Python

## Project Structure
- `mobile/` - frontend app
- `backend/` - FastAPI backend

## How to Run

### Backend
```bash
cd backend
python -m venv venv
.\venv\Scripts\Activate
pip install fastapi uvicorn
uvicorn main:app --reload --host 0.0.0.0 --port 8000