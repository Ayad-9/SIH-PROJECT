# SIH-PROJECT

A modern full-stack web application workspace for Smart India Hackathon (SIH), built with a **FastAPI** Python backend and a **React (Vite)** frontend.

---

## 📁 Project Architecture

```text
SIH-PROJECT/
├── backend/
│   ├── app/
│   │   ├── api/
│   │   │   └── routes.py      # API endpoints and route definitions
│   │   └── core/              # Config, DB, and utility modules
│   ├── main.py                # FastAPI entry point & CORS configuration
│   ├── requirements.txt       # Python dependencies
│   └── .env.example           # Example environment variables
├── frontend/
│   ├── src/
│   │   ├── App.jsx            # Main dashboard component with API status checker
│   │   ├── main.jsx           # React DOM root
│   │   └── index.css          # Base styling
│   ├── package.json
│   ├── vite.config.js
│   └── index.html
├── .gitignore
└── README.md
```

---

## 🚀 Getting Started

### 1. Backend Setup (FastAPI)

1. Open a terminal and navigate to the `backend/` directory:
   ```bash
   cd backend
   ```
2. Create and activate a Python virtual environment:
   ```bash
   # Windows (PowerShell)
   python -m venv venv
   .\venv\Scripts\Activate.ps1

   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Start the development server:
   ```bash
   uvicorn main:app --reload --port 8000
   ```
5. Interactive API documentation is available at:
   - **Swagger UI**: [http://localhost:8000/docs](http://localhost:8000/docs)
   - **ReDoc**: [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

### 2. Frontend Setup (React + Vite)

1. Open a new terminal and navigate to the `frontend/` directory:
   ```bash
   cd frontend
   ```
2. Install Node dependencies:
   ```bash
   npm install
   ```
3. Start the Vite development server:
   ```bash
   npm run dev
   ```
4. Open your browser at [http://localhost:5173](http://localhost:5173).

---

## 🛠 Tech Stack

- **Frontend**: React 19, Vite, Lucide Icons
- **Backend**: FastAPI, Uvicorn, Pydantic
- **Repository**: [https://github.com/Ayad-9/SIH-PROJECT](https://github.com/Ayad-9/SIH-PROJECT)