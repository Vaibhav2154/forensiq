import os
import logging
from dotenv import load_dotenv

load_dotenv()

class Config:
    GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
    CHROMA_PERSIST_DIRECTORY = os.getenv("CHROMA_PERSIST_DIRECTORY", "./chroma_db")
    EMBEDDING_MODEL = "all-MiniLM-L6-v2"
    
    # Server Configuration
    HOST = os.getenv("HOST", "0.0.0.0")
    PORT = int(os.getenv("PORT", 8000))  # Render sets PORT env variable
    
    # AWS Configuration for Bedrock Titan
    AWS_REGION = os.getenv("AWS_REGION", "us-east-1")
    AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
    
    ATTACK_DATA_PATH = os.path.join(os.path.dirname(__file__), "attack-stix-data", "enterprise-attack", "enterprise-attack-17.1.json")
    
    LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
    
    MAX_LOG_LENGTH = 10000
    MAX_RESULTS = 5 

logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)
