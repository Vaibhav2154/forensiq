"""
MongoDB service for storing and retrieving analysis data.
"""

import hashlib
import json
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
from motor.motor_asyncio import AsyncIOMotorCollection

from db import analysis_collection, monitoring_collection
from model.analysis_storage import StoredAnalysis, MonitoringSession, AnalysisStats
from core import logger

class AnalysisStorageService:
    """Service for storing and retrieving analysis data in MongoDB."""
    
    def __init__(self):
        self.analysis_collection: AsyncIOMotorCollection = analysis_collection
        self.monitoring_collection: AsyncIOMotorCollection = monitoring_collection
        self.logger = logger
    
    async def store_analysis(self, 
                           username: str,
                           log_content: str,
                           analysis_result: Dict[str, Any],
                           session_id: Optional[str] = None,
                           log_file_path: Optional[str] = None) -> str:
        """
        Store analysis result in MongoDB.
        
        Args:
            username: User who requested the analysis
            log_content: Original log content
            analysis_result: Analysis result from API
            session_id: Associated monitoring session ID
            log_file_path: Path to original log file
            
        Returns:
            str: Analysis ID
        """
        try:
            # Generate analysis ID and content hash
            analysis_id = hashlib.sha256(f"{username}_{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]
            content_hash = hashlib.sha256(log_content.encode()).hexdigest()
            
            # Extract AI agent data if available
            ai_agent_data = analysis_result.get('ai_agent_analysis')
            detected_patterns = ai_agent_data.get('detected_patterns') if ai_agent_data else None
            threat_context = ai_agent_data.get('threat_context') if ai_agent_data else None
            
            # Create stored analysis document
            stored_analysis = StoredAnalysis(
                analysis_id=analysis_id,
                session_id=session_id,
                username=username,
                log_content_hash=content_hash,
                log_file_path=log_file_path,
                summary=analysis_result.get('summary', ''),
                matched_techniques=analysis_result.get('matched_techniques', []),
                enhanced_analysis=analysis_result.get('enhanced_analysis'),
                processing_time_ms=analysis_result.get('processing_time_ms'),
                ai_agent_analysis=ai_agent_data,
                detected_patterns=detected_patterns,
                threat_context=threat_context,
                file_size=len(log_content),
                enhance_with_ai=analysis_result.get('enhance_with_ai', True),
                max_results=len(analysis_result.get('matched_techniques', []))
            )
            
            # Insert into MongoDB
            result = await self.analysis_collection.insert_one(stored_analysis.model_dump())
            
            # Update monitoring session if provided
            if session_id:
                await self.update_session_stats(session_id)
            
            self.logger.info(f"Analysis stored successfully with ID: {analysis_id}")
            return analysis_id
            
        except Exception as e:
            self.logger.error(f"Failed to store analysis: {e}")
            raise
    
    async def get_analysis(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve analysis by ID."""
        try:
            result = await self.analysis_collection.find_one({"analysis_id": analysis_id})
            if result:
                # Remove MongoDB _id field
                result.pop('_id', None)
                return result
            return None
        except Exception as e:
            self.logger.error(f"Failed to retrieve analysis {analysis_id}: {e}")
            return None
    
    async def get_user_analyses(self, username: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent analyses for a user."""
        try:
            cursor = self.analysis_collection.find(
                {"username": username}
            ).sort("created_at", -1).limit(limit)
            
            analyses = []
            async for doc in cursor:
                doc.pop('_id', None)
                analyses.append(doc)
            
            return analyses
        except Exception as e:
            self.logger.error(f"Failed to retrieve user analyses: {e}")
            return []
    
    async def create_monitoring_session(self, 
                                      username: str,
                                      log_path: str,
                                      interval_seconds: int = 300,
                                      ai_agent_enabled: bool = True) -> str:
        """
        Create a new monitoring session.
        
        Returns:
            str: Session ID
        """
        try:
            session_id = hashlib.sha256(f"{username}_{log_path}_{datetime.utcnow().isoformat()}".encode()).hexdigest()[:16]
            
            session = MonitoringSession(
                session_id=session_id,
                username=username,
                log_path=log_path,
                interval_seconds=interval_seconds,
                ai_agent_enabled=ai_agent_enabled
            )
            
            await self.monitoring_collection.insert_one(session.model_dump())
            self.logger.info(f"Monitoring session created: {session_id}")
            
            return session_id
        except Exception as e:
            self.logger.error(f"Failed to create monitoring session: {e}")
            raise
    
    async def get_monitoring_session(self, session_id: str) -> Optional[Dict[str, Any]]:
        """Get monitoring session by ID."""
        try:
            result = await self.monitoring_collection.find_one({"session_id": session_id})
            if result:
                result.pop('_id', None)
                return result
            return None
        except Exception as e:
            self.logger.error(f"Failed to retrieve monitoring session: {e}")
            return None
    
    async def update_session_stats(self, session_id: str) -> None:
        """Update monitoring session statistics."""
        try:
            await self.monitoring_collection.update_one(
                {"session_id": session_id},
                {
                    "$inc": {"total_analyses": 1},
                    "$set": {"last_analysis": datetime.utcnow()}
                }
            )
        except Exception as e:
            self.logger.error(f"Failed to update session stats: {e}")
    
    async def stop_monitoring_session(self, session_id: str) -> bool:
        """Stop a monitoring session."""
        try:
            result = await self.monitoring_collection.update_one(
                {"session_id": session_id, "status": "active"},
                {
                    "$set": {
                        "status": "stopped",
                        "end_time": datetime.utcnow()
                    }
                }
            )
            return result.modified_count > 0
        except Exception as e:
            self.logger.error(f"Failed to stop monitoring session: {e}")
            return False
    
    async def get_active_sessions(self, username: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get active monitoring sessions."""
        try:
            query = {"status": "active"}
            if username:
                query["username"] = username
            
            cursor = self.monitoring_collection.find(query).sort("start_time", -1)
            
            sessions = []
            async for doc in cursor:
                doc.pop('_id', None)
                sessions.append(doc)
            
            return sessions
        except Exception as e:
            self.logger.error(f"Failed to retrieve active sessions: {e}")
            return []
    
    async def get_analysis_stats(self, days: int = 30) -> AnalysisStats:
        """Get analysis statistics."""
        try:
            # Calculate date range
            end_date = datetime.utcnow()
            start_date = end_date - timedelta(days=days)
            today_start = datetime.utcnow().replace(hour=0, minute=0, second=0, microsecond=0)
            
            # Aggregate statistics
            pipeline = [
                {
                    "$facet": {
                        "total_analyses": [
                            {"$match": {"created_at": {"$gte": start_date}}},
                            {"$count": "count"}
                        ],
                        "analyses_today": [
                            {"$match": {"created_at": {"$gte": today_start}}},
                            {"$count": "count"}
                        ],
                        "unique_users": [
                            {"$match": {"created_at": {"$gte": start_date}}},
                            {"$group": {"_id": "$username"}},
                            {"$count": "count"}
                        ],
                        "top_techniques": [
                            {"$match": {"created_at": {"$gte": start_date}}},
                            {"$unwind": "$matched_techniques"},
                            {
                                "$group": {
                                    "_id": "$matched_techniques.technique_id",
                                    "name": {"$first": "$matched_techniques.name"},
                                    "count": {"$sum": 1},
                                    "avg_relevance": {"$avg": "$matched_techniques.relevance_score"}
                                }
                            },
                            {"$sort": {"count": -1}},
                            {"$limit": 10}
                        ],
                        "avg_processing_time": [
                            {"$match": {"created_at": {"$gte": start_date}, "processing_time_ms": {"$exists": True}}},
                            {"$group": {"_id": None, "avg_time": {"$avg": "$processing_time_ms"}}}
                        ]
                    }
                }
            ]
            
            result = await self.analysis_collection.aggregate(pipeline).to_list(1)
            stats_data = result[0] if result else {}
            
            # Extract values with defaults
            total_analyses = stats_data.get('total_analyses', [{}])[0].get('count', 0)
            analyses_today = stats_data.get('analyses_today', [{}])[0].get('count', 0)
            unique_users = stats_data.get('unique_users', [{}])[0].get('count', 0)
            top_techniques = stats_data.get('top_techniques', [])
            avg_time = stats_data.get('avg_processing_time', [{}])[0].get('avg_time', 0.0)
            
            # Get active sessions count
            active_sessions = len(await self.get_active_sessions())
            
            return AnalysisStats(
                total_analyses=total_analyses,
                analyses_today=analyses_today,
                unique_users=unique_users,
                active_sessions=active_sessions,
                top_techniques=top_techniques,
                average_processing_time=avg_time
            )
            
        except Exception as e:
            self.logger.error(f"Failed to get analysis stats: {e}")
            return AnalysisStats(
                total_analyses=0,
                analyses_today=0,
                unique_users=0,
                active_sessions=0,
                top_techniques=[],
                average_processing_time=0.0
            )
    
    async def cleanup_old_analyses(self, days: int = 90) -> int:
        """Clean up old analysis records."""
        try:
            cutoff_date = datetime.utcnow() - timedelta(days=days)
            result = await self.analysis_collection.delete_many(
                {"created_at": {"$lt": cutoff_date}}
            )
            self.logger.info(f"Cleaned up {result.deleted_count} old analysis records")
            return result.deleted_count
        except Exception as e:
            self.logger.error(f"Failed to cleanup old analyses: {e}")
            return 0
