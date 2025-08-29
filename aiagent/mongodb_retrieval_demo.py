#!/usr/bin/env python3
"""
MongoDB Retrieval Demo for ForensIQ CLI Tool

This script demonstrates how to retrieve data from MongoDB collections
using the ForensIQ CLI tool's data retrieval commands.
"""

import asyncio
import json
from datetime import datetime
from pathlib import Path

# Sample data that would be stored in MongoDB
SAMPLE_ANALYSIS_DATA = [
    {
        "_id": "64f7b8c9e123456789abcdef",
        "username": "admin",
        "timestamp": "2025-08-29T15:30:45.123Z",
        "log_source": "security_events",
        "summary": "Detected multiple failed login attempts and privilege escalation attempts from suspicious IP addresses",
        "matched_techniques": [
            {
                "technique_id": "T1078",
                "name": "Valid Accounts",
                "relevance_score": 0.92
            },
            {
                "technique_id": "T1110", 
                "name": "Brute Force",
                "relevance_score": 0.88
            },
            {
                "technique_id": "T1548",
                "name": "Abuse Elevation Control Mechanism",
                "relevance_score": 0.75
            }
        ],
        "ai_enhanced": True,
        "threat_score": 0.87
    },
    {
        "_id": "64f7b8c9e123456789abcde0",
        "username": "analyst01",
        "timestamp": "2025-08-29T15:25:30.456Z", 
        "log_source": "network_connections",
        "summary": "Unusual outbound network connections to external domains during off-hours",
        "matched_techniques": [
            {
                "technique_id": "T1071",
                "name": "Application Layer Protocol",
                "relevance_score": 0.65
            }
        ],
        "ai_enhanced": True,
        "threat_score": 0.45
    }
]

SAMPLE_SESSION_DATA = [
    {
        "_id": "64f7b8c9e123456789abcde1",
        "username": "admin",
        "start_time": "2025-08-29T14:00:00.000Z",
        "status": "active",
        "interval": 300,
        "log_sources": ["security_events", "system_events"],
        "total_analyses": 24,
        "last_analysis": "2025-08-29T15:25:00.000Z"
    },
    {
        "_id": "64f7b8c9e123456789abcde2", 
        "username": "analyst01",
        "start_time": "2025-08-29T13:30:00.000Z",
        "status": "completed",
        "interval": 600,
        "log_sources": ["network_connections"],
        "total_analyses": 12,
        "last_analysis": "2025-08-29T15:00:00.000Z"
    }
]

SAMPLE_STATS_DATA = {
    "log_analysis": {
        "count": 1247,
        "size": 2456789,
        "last_updated": "2025-08-29T15:30:45.123Z"
    },
    "monitoring_sessions": {
        "count": 15,
        "size": 45632,
        "last_updated": "2025-08-29T15:25:12.456Z"
    },
    "users": {
        "count": 8,
        "size": 12345,
        "last_updated": "2025-08-29T12:00:00.000Z"
    }
}

def demo_analysis_display(data):
    """Demo the analysis data display format."""
    print(f"\n📊 Analysis Data ({len(data)} records):")
    print("=" * 80)
    
    for i, record in enumerate(data, 1):
        print(f"\n{i}. Analysis ID: {record.get('_id', 'N/A')}")
        print(f"   User: {record.get('username', 'N/A')}")
        print(f"   Timestamp: {record.get('timestamp', 'N/A')}")
        print(f"   Log Source: {record.get('log_source', 'N/A')}")
        print(f"   Summary: {record.get('summary', 'N/A')[:100]}...")
        
        techniques = record.get('matched_techniques', [])
        if techniques:
            print(f"   MITRE Techniques ({len(techniques)}):")
            for tech in techniques[:3]:  # Show first 3 techniques
                print(f"     • {tech.get('technique_id', 'N/A')}: {tech.get('name', 'N/A')}")
            if len(techniques) > 3:
                print(f"     ... and {len(techniques) - 3} more")
        
        if record.get('ai_enhanced'):
            print(f"   AI Enhanced: ✓")
            if record.get('threat_score'):
                print(f"   Threat Score: {record.get('threat_score'):.2f}")

def demo_sessions_display(sessions):
    """Demo the monitoring sessions display format."""
    print(f"\n🔍 Monitoring Sessions ({len(sessions)} records):")
    print("=" * 80)
    
    for i, session in enumerate(sessions, 1):
        print(f"\n{i}. Session ID: {session.get('_id', 'N/A')}")
        print(f"   User: {session.get('username', 'N/A')}")
        print(f"   Started: {session.get('start_time', 'N/A')}")
        print(f"   Status: {session.get('status', 'N/A')}")
        print(f"   Interval: {session.get('interval', 'N/A')} seconds")
        
        sources = session.get('log_sources', [])
        if sources:
            print(f"   Log Sources: {', '.join(sources)}")
        
        print(f"   Total Analyses: {session.get('total_analyses', 0)}")
        if session.get('last_analysis'):
            print(f"   Last Analysis: {session.get('last_analysis')}")

def demo_stats_display(stats):
    """Demo the collection statistics display format."""
    print("\n📈 MongoDB Collection Statistics:")
    print("=" * 50)
    
    for collection, data in stats.items():
        if isinstance(data, dict):
            print(f"\n🗃️  {collection.replace('_', ' ').title()}:")
            print(f"   Total Records: {data.get('count', 0):,}")
            print(f"   Storage Size: {data.get('size', 0):,} bytes")
            if data.get('last_updated'):
                print(f"   Last Updated: {data.get('last_updated')}")

def demo_export_functionality():
    """Demo the export functionality."""
    print("\n💾 Export Functionality Demo:")
    print("=" * 40)
    
    # Demo JSON export
    export_dir = Path("demo_exports")
    export_dir.mkdir(exist_ok=True)
    
    json_file = export_dir / "sample_analysis.json"
    csv_file = export_dir / "sample_analysis.csv"
    
    # Export JSON
    with open(json_file, 'w') as f:
        json.dump(SAMPLE_ANALYSIS_DATA, f, indent=2)
    print(f"✓ JSON export saved: {json_file}")
    
    # Export CSV (simplified)
    import csv
    with open(csv_file, 'w', newline='') as f:
        if SAMPLE_ANALYSIS_DATA:
            # Flatten the data for CSV
            flattened_data = []
            for record in SAMPLE_ANALYSIS_DATA:
                flat_record = {
                    'id': record.get('_id'),
                    'username': record.get('username'),
                    'timestamp': record.get('timestamp'),
                    'log_source': record.get('log_source'),
                    'summary': record.get('summary'),
                    'technique_count': len(record.get('matched_techniques', [])),
                    'threat_score': record.get('threat_score'),
                    'ai_enhanced': record.get('ai_enhanced')
                }
                flattened_data.append(flat_record)
            
            writer = csv.DictWriter(f, fieldnames=flattened_data[0].keys())
            writer.writeheader()
            writer.writerows(flattened_data)
    
    print(f"✓ CSV export saved: {csv_file}")
    print(f"✓ Exports created in: {export_dir.absolute()}")

def main():
    """Run the MongoDB retrieval demo."""
    print("ForensIQ MongoDB Data Retrieval - DEMO")
    print("=" * 50)
    
    print("\n🎯 This demo shows how the CLI tool displays MongoDB data")
    print("   In practice, this data comes from your MongoDB collections")
    print("   populated by the 5-minute automated monitoring system.\n")
    
    # Demo Analysis Data Display
    print("1️⃣  ANALYSIS DATA DISPLAY")
    demo_analysis_display(SAMPLE_ANALYSIS_DATA)
    
    # Demo Sessions Display  
    print("\n\n2️⃣  MONITORING SESSIONS DISPLAY")
    demo_sessions_display(SAMPLE_SESSION_DATA)
    
    # Demo Stats Display
    print("\n\n3️⃣  COLLECTION STATISTICS DISPLAY")
    demo_stats_display(SAMPLE_STATS_DATA)
    
    # Demo Export
    print("\n\n4️⃣  EXPORT FUNCTIONALITY")
    demo_export_functionality()
    
    print("\n\n🚀 ACTUAL CLI COMMANDS TO USE:")
    print("=" * 40)
    print("# List all collections")
    print("python cli_tool.py data list")
    print("\n# Get latest analysis data")
    print("python cli_tool.py data analysis --limit 10")
    print("\n# Get monitoring sessions")
    print("python cli_tool.py data sessions --limit 5")
    print("\n# Get collection statistics")
    print("python cli_tool.py data stats")
    print("\n# Export data to file")
    print("python cli_tool.py data analysis --export analysis.json --limit 100")
    print("python cli_tool.py data sessions --export sessions.csv --format csv")
    
    print("\n\n✅ INTEGRATION WITH 5-MINUTE MONITORING:")
    print("=" * 50)
    print("• Every 5 minutes, the monitoring system extracts logs")
    print("• Logs are analyzed by the ForensIQ API")  
    print("• Results are automatically stored in MongoDB")
    print("• Use these commands to retrieve and analyze stored data")
    print("• Perfect for reporting, auditing, and trend analysis")
    
    print(f"\n📅 Demo completed at: {datetime.now()}")

if __name__ == "__main__":
    main()
