from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .routers import users

app = FastAPI(
    title="Authentication API",
    description="FastAPI Authentication & Authorization API with MongoDB, JWT and OAuth2",
    version="1.0.0",
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Production-এ নির্দিষ্ট domain দিন
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Root Route
@app.get("/")
async def root():
    return {
        "message": "Authentication API is running 🚀"
    }

# Health Check
@app.get("/health")
async def health():
    return {
        "status": "OK"
    }

# Register all routers
app.include_router(users.router)