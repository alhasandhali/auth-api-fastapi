"""Authentication API — FastAPI application entry point."""

import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .database import create_indexes, close_connection
from .routers import users

logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage startup and shutdown lifecycle events."""
    # Startup
    await create_indexes()
    logger.info("Auth API started")
    yield
    # Shutdown
    await close_connection()
    logger.info("Auth API shut down")


app = FastAPI(
    title="Authentication API",
    description="FastAPI Authentication & Authorization API with MongoDB, JWT and OAuth2",
    version="1.0.0",
    lifespan=lifespan,
)

# CORS — restrict allow_origins to your frontend domain(s) in production
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
async def root() -> dict:
    """Root endpoint confirming the API is running."""
    return {
        "message": "Authentication API is running 🚀",
    }


@app.get("/health")
async def health() -> dict:
    """Health check endpoint."""
    return {
        "status": "OK",
    }


# Register all routers
app.include_router(users.router)