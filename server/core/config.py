from pydantic_settings import BaseSettings,SettingsConfigDict


class Settings(BaseSettings):
  MONGO_URL: str
  SECRET_KEY: str
  ALGORITHM: str = "HS256"
  ACCESS_TOKEN_EXPIRE_MINUTES: int = 30
  AWS_ACCESS_KEY_ID: str 
  AWS_SECRET_ACCESS_KEY: str 
  AWS_REGION: str 
  AWS_SESSION_TOKEN : str
  
  model_config = SettingsConfigDict(env_file=".env")
  
settings = Settings()