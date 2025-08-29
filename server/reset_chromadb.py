#!/usr/bin/env python3
"""
Script to reset and reinitialize ChromaDB with MITRE ATT&CK data.
"""

import os
import sys
import asyncio
from pathlib import Path

# Add the server directory to Python path
server_dir = Path(__file__).parent
sys.path.insert(0, str(server_dir))

from services.chromadb_service import ChromaDBService
from core import logger

async def reset_chromadb():
    """Reset ChromaDB and reload MITRE ATT&CK data."""
    try:
        logger.info("Initializing ChromaDB service...")
        service = ChromaDBService()
        
        logger.info("ChromaDB service initialized successfully!")
        logger.info("MITRE ATT&CK data should be automatically loaded.")
        
        # Test the service
        test_results = await service.search_techniques("system compromise", n_results=3)
        logger.info(f"Test search returned {len(test_results)} results")
        
        return True
        
    except Exception as e:
        logger.error(f"Error resetting ChromaDB: {str(e)}")
        return False

if __name__ == "__main__":
    success = asyncio.run(reset_chromadb())
    if success:
        print("✅ ChromaDB reset successfully!")
        sys.exit(0)
    else:
        print("❌ Failed to reset ChromaDB")
        sys.exit(1)
