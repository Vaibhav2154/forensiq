from pydantic_settings import BaseSettings, SettingsConfigDict
import os
import logging
from dotenv import load_dotenv

load_dotenv()


class Settings(BaseSettings):
  MONGO_URL: str
  SECRET_KEY: str
  ALGORITHM: str = "HS256"
  ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
  
  # ForensIQ specific settings
  GEMINI_API_KEY: str
  CHROMA_PERSIST_DIRECTORY: str = "./chroma_db"
  ANONYMIZED_TELEMETRY: str = "False"
  LOG_LEVEL: str = "INFO"
  API_HOST: str = "localhost"
  API_PORT: str = "8000"
  MAX_LOG_LENGTH: str = "10000"
  MAX_RESULTS: str = "5"
  
  model_config = SettingsConfigDict(env_file=".env")


settings = Settings()


class Config:
    GEMINI_API_KEY = settings.GEMINI_API_KEY
    CHROMA_PERSIST_DIRECTORY = settings.CHROMA_PERSIST_DIRECTORY
    EMBEDDING_MODEL = "all-MiniLM-L6-v2"
    
    ATTACK_DATA_PATH = "./attack-stix-data/enterprise-attack/enterprise-attack-17.1.json"
    
    LOG_LEVEL = settings.LOG_LEVEL
    
    MAX_LOG_LENGTH = int(settings.MAX_LOG_LENGTH)
    MAX_RESULTS = int(settings.MAX_RESULTS)

logging.basicConfig(
    level=getattr(logging, Config.LOG_LEVEL),
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)