#!/usr/bin/env python3
"""
Test MongoDB Connection for ForensIQ CLI Tool

This script tests the MongoDB connection using the same configuration as the server.
"""

import asyncio
import os
from pathlib import Path
from dotenv import load_dotenv

# Load environment from server directory
server_dir = Path(__file__).parent.parent / "server"
env_file = server_dir / ".env"

print(f"Looking for .env file at: {env_file}")
print(f"File exists: {env_file.exists()}")

if env_file.exists():
    load_dotenv(env_file)
    print("✓ Loaded .env from server directory")
else:
    # Try loading from current directory
    load_dotenv()
    print("✓ Loaded .env from current directory")

mongo_url = os.getenv('MONGO_URL')
print(f"MongoDB URL: {mongo_url[:50]}..." if mongo_url else "MongoDB URL: Not found")

async def test_mongodb_connection():
    """Test MongoDB connection."""
    try:
        from motor.motor_asyncio import AsyncIOMotorClient
        
        if not mongo_url:
            print("❌ MONGO_URL not found in environment variables")
            return False
        
        print(f"🔗 Connecting to MongoDB...")
        client = AsyncIOMotorClient(mongo_url)
        
        # Test connection
        await client.admin.command('ping')
        print("✅ MongoDB connection successful!")
        
        # Test database access
        database = client.Forensiq
        
        # Check existing collections
        collections = await database.list_collection_names()
        print(f"📋 Available collections: {collections}")
        
        # Check user collection
        user_collection = database.get_collection("users")
        user_count = await user_collection.count_documents({})
        print(f"👤 Users in database: {user_count}")
        
        # Check analysis collection
        analysis_collection = database.get_collection("log_analysis")
        analysis_count = await analysis_collection.count_documents({})
        print(f"📊 Analysis records: {analysis_count}")
        
        # Check monitoring collection
        monitoring_collection = database.get_collection("monitoring_sessions")
        monitoring_count = await monitoring_collection.count_documents({})
        print(f"🔍 Monitoring sessions: {monitoring_count}")
        
        client.close()
        return True
        
    except Exception as e:
        print(f"❌ MongoDB connection failed: {e}")
        return False

async def main():
    """Main test function."""
    print("ForensIQ MongoDB Connection Test")
    print("=" * 40)
    
    success = await test_mongodb_connection()
    
    if success:
        print("\n✅ MongoDB integration is ready!")
        print("You can now use the CLI tool with real MongoDB storage.")
    else:
        print("\n❌ MongoDB connection failed!")
        print("Please check your .env file and MongoDB server.")
        print(f"Expected .env location: {env_file}")

if __name__ == "__main__":
    asyncio.run(main())
