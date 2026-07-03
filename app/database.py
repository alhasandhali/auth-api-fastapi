import os
from dotenv import load_dotenv
from motor.motor_asyncio import AsyncIOMotorClient

load_dotenv()

DB_USER = os.getenv("DB_USER")
DB_PASS = os.getenv("DB_PASS")

DATABASE_URL = (
    f"mongodb+srv://{DB_USER}:{DB_PASS}"
    "@cluster-1.dymuola.mongodb.net/"
    "?retryWrites=true&w=majority&appName=Cluster-1"
)

client = AsyncIOMotorClient(DATABASE_URL)

db = client["auth_db"]  # Database name
users_collection = db["users"]