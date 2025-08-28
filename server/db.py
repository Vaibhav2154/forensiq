from motor.motor_asyncio import AsyncIOMotorClient
from core.config import settings

client = AsyncIOMotorClient(settings.MONGO_URL)
database = client.Forensiq
user_collection = database.get_collection("users")