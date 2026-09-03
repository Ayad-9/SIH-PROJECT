from fastapi import APIRouter
from datetime import datetime

router = APIRouter()

@router.get("/health")
def health_check():
    return {
        "status": "online",
        "service": "SIH-PROJECT API",
        "timestamp": datetime.utcnow().isoformat()
    }

@router.get("/demo-data")
def get_demo_data():
    return {
        "message": "Welcome to SIH-PROJECT API!",
        "features": [
            "FastAPI Async Backend",
            "Auto-generated Swagger Docs at /docs",
            "CORS Enabled for React Frontend",
            "Modular Architecture"
        ]
    }
