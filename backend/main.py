import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from dotenv import load_dotenv
from app.api.routes import router as api_router

load_dotenv()

app = FastAPI(
    title="SIH-PROJECT Backend",
    description="Backend API service for SIH Project",
    version="1.0.0"
)

# Enable CORS for frontend development
origins = [
    "http://localhost:5173",
    "http://127.0.0.1:5173",
    os.getenv("FRONTEND_URL", "http://localhost:5173")
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router, prefix="/api")

@app.get("/")
def root():
    return {
        "name": "SIH-PROJECT API",
        "version": "1.0.0",
        "docs_url": "/docs",
        "status": "running"
    }

if __name__ == "__main__":
    import uvicorn
    port = int(os.getenv("PORT", 8000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=True)
