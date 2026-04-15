from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from detector import analyze_text

app = FastAPI(title="PhishGuard AI API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class AnalyzeRequest(BaseModel):
    input_text: str
    input_type: str

@app.get("/")
def home():
    return {"message": "PhishGuard AI backend is running"}

@app.post("/analyze")
def analyze(payload: AnalyzeRequest):
    return analyze_text(payload.input_text, payload.input_type)