"""
MongoDB service for storing and retrieving encrypted analysis data.
"""

from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import uuid
from bson import ObjectId
from services.encryption_service import encryption_service
from db import database
from core import logger

class AnalysisStorageService:
    """Service for storing and retrieving encrypted analysis data in MongoDB."""
    
    def __init__(self):
        self.collection = database.get_collection("analysis_results")
        self.sessions_collection = database.get_collection("monitoring_sessions")
    
    async def store_analysis_result(self, user_id: str, request, response) -> str:
        """Store encrypted analysis result."""
        try:
            # Helper function to convert datetime objects to strings recursively
            def convert_datetimes_to_strings(obj):
                if hasattr(obj, 'isoformat'):  # datetime object
                    return obj.isoformat()
                elif isinstance(obj, dict):
                    return {key: convert_datetimes_to_strings(value) for key, value in obj.items()}
                elif isinstance(obj, list):
                    return [convert_datetimes_to_strings(item) for item in obj]
                else:
                    return obj
            
            # Debug what we received
            logger.info(f"Processing {len(response.matched_techniques)} techniques for storage")
            for i, tech in enumerate(response.matched_techniques):
                logger.info(f"Technique {i}: {tech} (has model_dump: {hasattr(tech, 'model_dump')})")
                if hasattr(tech, 'model_dump'):
                    tech_data = tech.model_dump()
                    logger.info(f"Technique {i} data: {tech_data}")
            
            # Convert techniques to serializable format
            serializable_techniques = []
            for tech in response.matched_techniques:
                if hasattr(tech, 'model_dump'):
                    tech_dict = tech.model_dump()
                    serializable_tech = convert_datetimes_to_strings(tech_dict)
                    serializable_techniques.append(serializable_tech)
                    logger.info(f"Added technique to serializable list: {serializable_tech}")
                else:
                    logger.warning(f"Technique {tech} does not have model_dump method!")
            
            # Convert summary and enhanced_analysis if they contain datetime objects
            clean_summary = convert_datetimes_to_strings(response.summary)
            clean_enhanced_analysis = convert_datetimes_to_strings(response.enhanced_analysis) if response.enhanced_analysis else None
            
            logger.info(f"Final data for encryption:")
            logger.info(f"  - Summary: '{clean_summary}' (len: {len(str(clean_summary))})")
            logger.info(f"  - Techniques: {len(serializable_techniques)} items")
            logger.info(f"  - Enhanced analysis: {clean_enhanced_analysis}")
            
            # Encrypt the analysis results
            encrypted_results, key_id = encryption_service.encrypt_analysis_results(
                summary=clean_summary,
                techniques=serializable_techniques,
                enhanced_analysis=clean_enhanced_analysis,
                user_id=user_id
            )
            
            # Create document
            document = {
                "user_id": user_id,
                "encrypted_summary": encrypted_results['summary'],
                "encrypted_techniques": encrypted_results['techniques'],
                "encrypted_enhanced_analysis": encrypted_results.get('enhanced_analysis'),
                "analysis_timestamp": datetime.utcnow(),
                "processing_time_ms": getattr(response, 'processing_time_ms', 0),
                "techniques_count": len(serializable_techniques),  # Use serializable_techniques count
                "encryption_key_id": key_id
            }
            
            logger.info(f"Document to store - techniques_count: {document['techniques_count']}")
            
            # Store in database
            result = await self.collection.insert_one(document)
            analysis_id = str(result.inserted_id)
            
            logger.info(f"Stored encrypted analysis {analysis_id} for user {user_id}")
            return analysis_id
            
        except Exception as e:
            logger.error(f"Failed to store analysis: {e}")
            raise
    
    async def get_analysis_result(self, user_id: str, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve and decrypt analysis result."""
        try:
            # Find document
            doc = await self.collection.find_one({
                "user_id": user_id,
                "_id": ObjectId(analysis_id)
            })
            
            if not doc:
                logger.warning(f"Analysis {analysis_id} not found for user {user_id}")
                return None
            
            # Decrypt all data at once
            encrypted_payload = {
                "summary": doc.get("encrypted_summary"),
                "techniques": doc.get("encrypted_techniques"),
                "enhanced_analysis": doc.get("encrypted_enhanced_analysis")
            }
            
            decrypted_data = encryption_service.decrypt_analysis_results(
                encrypted_data=encrypted_payload,
                user_id=user_id
            )
            
            return {
                "summary": decrypted_data.get("summary"),
                "matched_techniques": decrypted_data.get("techniques"),
                "enhanced_analysis": decrypted_data.get("enhanced_analysis"),
                "analysis_timestamp": doc.get("analysis_timestamp"),
                "processing_time_ms": doc.get("processing_time_ms", 0)
            }
            
        except Exception as e:
            logger.error(f"Failed to decrypt analysis {analysis_id}: {e}")
            return None
    
    async def get_user_analysis_history(self, user_id: str, limit: int = 50, offset: int = 0) -> List[Dict[str, Any]]:
        """Get user analysis history (metadata only)."""
        try:
            cursor = self.collection.find(
                {"user_id": user_id}
            ).sort("analysis_timestamp", -1).skip(offset).limit(limit)
            
            analyses = []
            async for doc in cursor:
                analyses.append({
                    "id": str(doc.get("_id")),
                    "analysis_timestamp": doc.get("analysis_timestamp"),
                    "processing_time_ms": doc.get("processing_time_ms", 0),
                    "techniques_count": doc.get("techniques_count", 0),
                    "logs_preview": "Preview unavailable"
                })
            
            return analyses
        except Exception as e:
            logger.error(f"Failed to get history: {e}")
            return []

    # ===== MONITORING SESSIONS =====
    async def create_monitoring_session(self, username: str, log_path: str, interval_seconds: int = 300, ai_agent_enabled: bool = True) -> str:
        """Create a new monitoring session."""
        try:
            session_id = str(uuid.uuid4())
            
            session_doc = {
                "session_id": session_id,
                "username": username,
                "log_path": log_path,
                "interval_seconds": interval_seconds,
                "ai_agent_enabled": ai_agent_enabled,
                "status": "active",
                "created_at": datetime.utcnow(),
                "last_checked": datetime.utcnow()
            }
            
            await self.sessions_collection.insert_one(session_doc)
            logger.info(f"Created monitoring session {session_id} for user {username}")
            return session_id
            
        except Exception as e:
            logger.error(f"Failed to create monitoring session: {e}")
            raise
    
    async def stop_monitoring_session(self, session_id: str) -> bool:
        """Stop a monitoring session."""
        try:
            result = await self.sessions_collection.update_one(
                {"session_id": session_id, "status": "active"},
                {"$set": {"status": "stopped", "stopped_at": datetime.utcnow()}}
            )
            return result.modified_count > 0
        except Exception as e:
            logger.error(f"Failed to stop monitoring session {session_id}: {e}")
            return False
    
    async def get_active_sessions(self, username: str) -> List[Dict[str, Any]]:
        """Get active monitoring sessions for user."""
        try:
            cursor = self.sessions_collection.find({
                "username": username,
                "status": "active"
            }).sort("created_at", -1)
            
            sessions = []
            async for doc in cursor:
                sessions.append({
                    "session_id": doc.get("session_id"),
                    "log_path": doc.get("log_path"),
                    "interval_seconds": doc.get("interval_seconds", 300),
                    "ai_agent_enabled": doc.get("ai_agent_enabled", True),
                    "status": doc.get("status"),
                    "created_at": doc.get("created_at"),
                    "last_checked": doc.get("last_checked")
                })
            
            return sessions
        except Exception as e:
            logger.error(f"Failed to get active sessions: {e}")
            return []
    
    async def get_monitoring_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get specific monitoring session."""
        try:
            doc = await self.sessions_collection.find_one({"session_id": session_id})
            if not doc:
                return None
            
            return {
                "session_id": doc.get("session_id"),
                "username": doc.get("username"),
                "log_path": doc.get("log_path"),
                "interval_seconds": doc.get("interval_seconds", 300),
                "ai_agent_enabled": doc.get("ai_agent_enabled", True),
                "status": doc.get("status"),
                "created_at": doc.get("created_at"),
                "last_checked": doc.get("last_checked"),
                "stopped_at": doc.get("stopped_at")
            }
        except Exception as e:
            logger.error(f"Failed to get monitoring session {session_id}: {e}")
            return None

    async def get_analysis_stats(self, days: int = 30) -> Dict[str, Any]:
        """Get analysis statistics."""
        try:
            since_date = datetime.utcnow() - timedelta(days=days)
            
            total_analyses = await self.collection.count_documents({
                "analysis_timestamp": {"$gte": since_date}
            })
            
            active_sessions = await self.sessions_collection.count_documents({
                "status": "active"
            })
            
            return {
                "total_analyses": total_analyses,
                "active_sessions": active_sessions,
                "period_days": days
            }
        except Exception as e:
            logger.error(f"Failed to get analysis stats: {e}")
            return {
                "total_analyses": 0,
                "active_sessions": 0,
                "period_days": days
            }

analysis_storage_service = AnalysisStorageService()

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

router = APIRouter()

# Request and response models
class StoreAnalysisRequest(BaseModel):
    log_content: str
    analysis_result: dict

class AnalysisResponse(BaseModel):
    analysis_id: str
    status: str
    message: str

# Dependency
async def get_current_user():
    # Mock implementation - replace with actual user retrieval logic
    return {"username": "test_user"}

@router.post("/analysis/store", response_model=AnalysisResponse)
async def store_analysis_result(
    request: StoreAnalysisRequest,
    current_user: dict = Depends(get_current_user)
):
    """Store analysis result in MongoDB."""
    try:
        user_id = current_user.get('username')
        
        # Debug what we received in the request
        logger.info(f"Received analysis request:")
        logger.info(f"  - Summary: '{request.analysis_result.get('summary', '')}' (len: {len(request.analysis_result.get('summary', ''))})")
        logger.info(f"  - Techniques: {request.analysis_result.get('matched_techniques', [])} (count: {len(request.analysis_result.get('matched_techniques', []))})")
        logger.info(f"  - Enhanced analysis: {request.analysis_result.get('enhanced_analysis', 'None')}")
        
        # Create technique objects that have model_dump method
        class TechniqueWrapper:
            def __init__(self, tech_data):
                self._data = tech_data
            
            def model_dump(self):
                return self._data
        
        # Create response object directly from your request data
        class DirectResponse:
            def __init__(self, analysis_result):
                # Use the actual data from your request
                self.summary = analysis_result.get('summary', '')
                self.enhanced_analysis = analysis_result.get('enhanced_analysis', None)
                self.processing_time_ms = analysis_result.get('processing_time_ms', 0)
                
                # Wrap each technique in an object with model_dump
                self.matched_techniques = []
                for tech_data in analysis_result.get('matched_techniques', []):
                    wrapped_tech = TechniqueWrapper(tech_data)
                    self.matched_techniques.append(wrapped_tech)
        
        class DirectRequest:
            def __init__(self, log_content):
                self.logs = log_content
        
        direct_request = DirectRequest(request.log_content)
        direct_response = DirectResponse(request.analysis_result)
        
        # Debug what we're about to store
        logger.info(f"About to store:")
        logger.info(f"  - Summary: '{direct_response.summary}' (len: {len(direct_response.summary)})")
        logger.info(f"  - Techniques count: {len(direct_response.matched_techniques)}")
        logger.info(f"  - Enhanced analysis: '{direct_response.enhanced_analysis}'")
        
        # Store using the storage service
        analysis_id = await analysis_storage_service.store_analysis_result(
            user_id=user_id,
            request=direct_request,
            response=direct_response
        )
        
        return AnalysisResponse(
            analysis_id=analysis_id,
            status="stored", 
            message="Analysis result stored successfully"
        )
        
    except Exception as e:
        logger.error(f"Failed to store analysis: {e}")
        raise HTTPException(status_code=500, detail=str(e))
