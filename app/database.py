"""MongoDB connection and collection references."""

import os
import logging

from motor.motor_asyncio import AsyncIOMotorClient

logger = logging.getLogger(__name__)

DB_USER: str | None = os.getenv("DB_USER")
DB_PASS: str | None = os.getenv("DB_PASS")

DATABASE_URL: str = (
    f"mongodb+srv://{DB_USER}:{DB_PASS}"
    "@cluster-1.dymuola.mongodb.net/"
    "?retryWrites=true&w=majority&appName=Cluster-1"
)

client: AsyncIOMotorClient = AsyncIOMotorClient(DATABASE_URL)

db = client["auth_db"]
users_collection = db["users"]


async def create_indexes() -> None:
    """Create database indexes for performance and data integrity."""
    await users_collection.create_index("username", unique=True)
    await users_collection.create_index("email", unique=True)
    logger.info("Database indexes ensured")


async def close_connection() -> None:
    """Close the MongoDB client connection."""
    client.close()
    logger.info("MongoDB connection closed")