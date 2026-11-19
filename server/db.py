from motor.motor_asyncio import AsyncIOMotorClient
from core.config import settings
import certifi

client = AsyncIOMotorClient(
	settings.MONGO_URL,
	tlsCAFile=certifi.where()
)
database = client.Forensiq
user_collection = database.get_collection("users")
analysis_collection = database.get_collection("analysis_results")
monitoring_collection = database.get_collection("monitoring_sessions")