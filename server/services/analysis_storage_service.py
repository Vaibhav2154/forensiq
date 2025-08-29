"""
MongoDB service for storing and retrieving encrypted analysis data.
"""

from datetime import datetime
from typing import Dict, Any, List, Optional

from db import database
from core import logger

class AnalysisStorageService:
    """Service for storing and retrieving encrypted analysis data in MongoDB."""
    
    def __init__(self):
        self.collection = database.get_collection("analysis_results")
    
    async def store_analysis_result(self, user_id: str, request, response) -> str:
        """Store encrypted analysis result."""
        try:
            from services.encryption_service import encryption_service
            
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
            
            # Convert techniques to serializable format
            serializable_techniques = []
            for tech in response.matched_techniques:
                tech_dict = tech.model_dump()
                # Convert any datetime objects to strings recursively
                serializable_tech = convert_datetimes_to_strings(tech_dict)
                serializable_techniques.append(serializable_tech)
            
            # Convert summary and enhanced_analysis if they contain datetime objects
            clean_summary = convert_datetimes_to_strings(response.summary)
            clean_enhanced_analysis = convert_datetimes_to_strings(response.enhanced_analysis) if response.enhanced_analysis else None
            
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
                "processing_time_ms": response.processing_time_ms or 0,
                "techniques_count": len(response.matched_techniques),
                "encryption_key_id": key_id
            }
            
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
            from services.encryption_service import encryption_service
            from bson import ObjectId
            
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
        """Get user analysis history."""
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

analysis_storage_service = AnalysisStorageService()
