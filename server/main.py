from fastapi import FastAPI
from routers import auth, users, analysis,analyzis
from services.bedrock_service import BedrockService

app = FastAPI()

@app.on_event("startup")
async def startup_event():
    """Initialize services on application startup."""
    print("Initializing services...")
    
    # Initialize only the BedrockService (replaces both Bedrock and Titan services)
    bedrock_service = BedrockService()
    
    # Set the service for the analysis router
    analysis.set_services(bedrock=bedrock_service)
    
    print("Services initialized successfully.")

app.include_router(auth.router)
app.include_router(users.router)
app.include_router(analysis.router)
app.include_router(analyzis.router)

@app.get('/')
async def read_root():
    return {"message": "Welcome to the ForensiQ API - Optimized with AWS Knowledge Base"}