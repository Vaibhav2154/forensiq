from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from contextlib import asynccontextmanager
from datetime import datetime

from core import Config, logger
from services import GeminiService, ChromaDBService, AWSBedrockService
from routers import auth, users, analysis_router, mitre
from routers import monitoring
from routers.analysis import set_services
from routers.mitre import set_mitre_services
from model import HealthCheck, ErrorResponse, DatabaseStats

gemini_service: GeminiService = None
chromadb_service: ChromaDBService = None
aws_bedrock_service: AWSBedrockService = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan - startup and shutdown events."""
    logger.info("Starting ForensIQ API server...")
    try:
        global gemini_service, chromadb_service, aws_bedrock_service
        logger.info("Initializing Gemini AI service...")
        gemini_service = GeminiService()
        logger.info("Initializing ChromaDB service...")
        chromadb_service = ChromaDBService()
        logger.info("Initializing AWS Bedrock service...")
        aws_bedrock_service = AWSBedrockService()
        logger.info("Initializing MITRE ATT&CK database...")
        db_initialized = await chromadb_service.initialize_database()
        if not db_initialized:
            logger.error("Failed to initialize database")
            raise Exception("Database initialization failed")
        # Set services for routers
        set_services(gemini_service, chromadb_service)
        set_mitre_services(aws_bedrock_service, chromadb_service, gemini_service)
        logger.info("All services initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize services: {str(e)}")
        raise
    yield
    logger.info("Shutting down ForensIQ API server...")

app = FastAPI(
    title="ForensIQ - MITRE ATT&CK Log Analysis API",
    description="AI-powered system log analysis with MITRE ATT&CK technique matching using Gemini AI and ChromaDB RAG",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*","localhost:3000"],  # Configure appropriately for production
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(auth.router)
app.include_router(users.router)
app.include_router(analysis_router)
app.include_router(monitoring.router)
app.include_router(mitre.router)

@app.get("/", response_model=dict)
async def root():
    """Root endpoint with API information."""
    return {
        "message": "ForensIQ - MITRE ATT&CK Log Analysis API",
        "version": "1.0.0",
        "description": "AI-powered system log analysis with MITRE ATT&CK technique matching",
        "docs": "/docs",
        "health": "/health",
        "timestamp": datetime.utcnow().isoformat()
    }

@app.get("/health", response_model=HealthCheck)
async def health_check():
    """Health check endpoint to verify all services are running."""
    try:
        services_status = {}
        # Check Gemini service
        if gemini_service:
            services_status["gemini_ai"] = "healthy"
        else:
            services_status["gemini_ai"] = "not_initialized"
            
        # Check AWS Bedrock service
        if aws_bedrock_service:
            services_status["aws_bedrock"] = "healthy"
        else:
            services_status["aws_bedrock"] = "not_initialized"
        if chromadb_service:
            try:
                stats = await chromadb_service.get_collection_stats()
                if "error" in stats:
                    services_status["chromadb"] = f"error: {stats['error']}"
                else:
                    services_status["chromadb"] = "healthy"
                    db_stats = DatabaseStats(
                        total_techniques=stats.get('total_techniques', 0),
                        collection_name=stats.get('collection_name', 'unknown'),
                        embedding_model=stats.get('embedding_model', 'unknown')
                    )
            except Exception as e:
                services_status["chromadb"] = f"error: {str(e)}"
                db_stats = None
        else:
            services_status["chromadb"] = "not_initialized"
            db_stats = None
        # Determine overall status
        overall_status = "healthy" if all(
            status == "healthy" for status in services_status.values()
        ) else "degraded"
        return HealthCheck(
            status=overall_status,
            services=services_status,
            database_stats=db_stats
        )
    except Exception as e:
        logger.error(f"Health check failed: {str(e)}")
        return HealthCheck(
            status="unhealthy",
            services={"error": str(e)}
        )

@app.exception_handler(Exception)
async def global_exception_handler(request, exc):
    """Global exception handler for unhandled errors."""
    logger.error(f"Unhandled exception: {str(exc)}")
    return JSONResponse(
        status_code=500,
        content=ErrorResponse(
            error="Internal server error",
            detail=str(exc)
        ).dict()
    )

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8000,,
        log_level=Config.LOG_LEVEL.lower()
    )