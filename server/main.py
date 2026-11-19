import os
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder
from contextlib import asynccontextmanager
from datetime import datetime
from core import Config, logger
from services import GeminiService
from services.investigation import InvestigationService
from services.knowledge import KnowledgeService
from routers import auth, users, analysis_router, mitre, knowledge_router, investigations_router
from routers import monitoring
from routers.analysis import set_services
from routers.investigations import set_investigation_service
from routers.mitre import set_mitre_services
from routers.knowledge import set_knowledge_service
from model import HealthCheck, ErrorResponse, DatabaseStats

gemini_service: GeminiService = None
knowledge_service: KnowledgeService = None
investigation_service: InvestigationService = None

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan - startup and shutdown events."""
    logger.info("Starting ForensIQ API server...")
    try:
        global gemini_service, knowledge_service, investigation_service
        logger.info("Initializing Gemini AI service...")
        gemini_service = GeminiService()
        logger.info("Initializing ForensIQ knowledge service (KCP/OKF/Cognee)...")
        knowledge_service = KnowledgeService()
        await knowledge_service.initialize()
        logger.info("Initializing ForensIQ LangGraph multi-agent investigation service...")
        investigation_service = InvestigationService(knowledge_service=knowledge_service)
        # Wire services into routers
        set_knowledge_service(knowledge_service)
        set_investigation_service(investigation_service)
        set_services(gemini_service, knowledge_service, investigation_service)
        set_mitre_services(knowledge_service, gemini_service)
        logger.info("All services initialized successfully")
    except Exception as e:
        logger.error(f"Failed to initialize services: {str(e)}")
        raise
    yield
    if knowledge_service is not None:
        try:
            await knowledge_service.close()
        except Exception as k_exc:
            logger.warning(f"Error closing knowledge service: {str(k_exc)}")
    logger.info("Shutting down ForensIQ API server...")

app = FastAPI(
    title="ForensIQ - MITRE ATT&CK & CVE Log Analysis API",
    description="AI-powered system log analysis with KCP normalization, OKF/Cognee knowledge retrieval, and LangGraph multi-agent investigation",
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
app.include_router(knowledge_router)
app.include_router(investigations_router)

@app.get("/", response_model=dict)
async def root():
    """Root endpoint with API information."""
    return {
            "message": "LogIQ - MITRE ATT&CK Log Analysis API",
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
        if investigation_service:
            services_status["multi_agent_investigation"] = "healthy"
        else:
            services_status["multi_agent_investigation"] = "not_initialized"
        db_stats = None
        if knowledge_service:
            try:
                k_stats = await knowledge_service.stats()
                services_status["knowledge"] = "healthy"
                db_stats = DatabaseStats(
                    total_techniques=k_stats.counts_by_kind.get("attack-pattern", k_stats.total_records),
                    collection_name=f"okf-{k_stats.backend}",
                    embedding_model=knowledge_service.settings.embedding_model,
                    last_updated=k_stats.last_ingested_at,
                )
            except Exception as e:
                services_status["knowledge"] = f"error: {str(e)}"
        else:
            services_status["knowledge"] = "not_initialized"
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
    logger.exception(f"Unhandled exception: {str(exc)}")
    error_payload = ErrorResponse(
        error="Internal server error",
        detail=str(exc)
    )
    return JSONResponse(
        status_code=500,
        content=jsonable_encoder(error_payload)
    )

if __name__ == "__main__":
    import uvicorn
    port = os.getenv("PORT", Config.PORT)
    uvicorn.run(
        "main:app",
        host=Config.HOST,
        port=port,
        log_level=Config.LOG_LEVEL.lower()
    )