#!/usr/bin/env python3
"""
ForensIQ Dynamic Monitoring Demo

This script demonstrates the complete workflow of dynamic log extraction,
analysis, and MongoDB storage with 5-minute intervals.
"""

import asyncio
import json
import time
import logging
from datetime import datetime, timedelta
from pathlib import Path

# Setup logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ForensIQMonitoringDemo:
    """Demonstrates the complete ForensIQ monitoring workflow."""
    
    def __init__(self):
        self.session_id = f"demo_session_{int(time.time())}"
        self.analysis_count = 0
        
    async def simulate_authentication(self):
        """Simulate successful authentication."""
        logger.info("🔐 Authenticating with ForensIQ server...")
        await asyncio.sleep(1)
        logger.info("✅ Authentication successful!")
        return True
    
    async def simulate_dynamic_log_extraction(self):
        """Simulate dynamic log extraction from system sources."""
        logger.info("📊 Extracting dynamic logs from system sources...")
        
        # Simulate extracted logs from different sources
        simulated_logs = {
            'security_events': [
                "2025-08-29 15:20:01 - Security Event: User login attempt from IP 192.168.1.100",
                "2025-08-29 15:20:05 - Security Event: Failed authentication for user 'admin'",
                "2025-08-29 15:20:10 - Security Event: Successful login for user 'vaibhav'"
            ],
            'system_events': [
                "2025-08-29 15:20:02 - System Event: Service 'Windows Update' started",
                "2025-08-29 15:20:07 - System Event: High memory usage detected (85%)",
                "2025-08-29 15:20:12 - System Event: Network adapter reset"
            ],
            'process_monitor': [
                "2025-08-29 15:20:03 - Process: New process created - powershell.exe (PID: 1234)",
                "2025-08-29 15:20:08 - Process: Process terminated - notepad.exe (PID: 5678)",
                "2025-08-29 15:20:13 - Process: Suspicious process - cmd.exe with elevated privileges"
            ]
        }
        
        # Combine all logs
        all_logs = []
        for source, logs in simulated_logs.items():
            for log in logs:
                all_logs.append(f"[{source.upper()}] {log}")
        
        combined_logs = "\n".join(all_logs)
        logger.info(f"✅ Extracted {len(all_logs)} log entries from {len(simulated_logs)} sources")
        
        return combined_logs
    
    async def simulate_ai_analysis(self, logs):
        """Simulate AI analysis of the extracted logs."""
        logger.info("🤖 Analyzing logs with AI agent...")
        await asyncio.sleep(2)  # Simulate analysis time
        
        # Simulate analysis results
        analysis_result = {
            "analysis_id": f"analysis_{self.analysis_count}_{int(time.time())}",
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": self.session_id,
            "summary": "AI analysis detected multiple security events including failed authentication attempts and suspicious process execution.",
            "matched_techniques": [
                {
                    "technique_id": "T1078",
                    "name": "Valid Accounts",
                    "description": "Failed login attempts may indicate credential stuffing or brute force attacks",
                    "kill_chain_phases": ["defense-evasion", "persistence", "privilege-escalation", "initial-access"],
                    "platforms": ["Windows", "Linux", "macOS"],
                    "relevance_score": 0.85
                },
                {
                    "technique_id": "T1059",
                    "name": "Command and Scripting Interpreter",
                    "description": "PowerShell and cmd.exe execution detected with potential privilege escalation",
                    "kill_chain_phases": ["execution"],
                    "platforms": ["Windows"],
                    "relevance_score": 0.72
                }
            ],
            "enhanced_analysis": "The logs show a pattern of failed authentication followed by successful login and process execution, which could indicate a successful attack progression.",
            "ai_agent_analysis": {
                "threat_level": "medium",
                "confidence_score": 0.78,
                "detected_patterns": 3,
                "recommendations": [
                    "Monitor user 'admin' for additional failed login attempts",
                    "Review PowerShell execution logs for suspicious commands",
                    "Implement account lockout policies for repeated failures"
                ]
            },
            "processing_time_ms": 2150.5
        }
        
        self.analysis_count += 1
        logger.info(f"✅ Analysis completed - Threat Level: {analysis_result['ai_agent_analysis']['threat_level'].upper()}")
        logger.info(f"   Detected {len(analysis_result['matched_techniques'])} MITRE ATT&CK techniques")
        
        return analysis_result
    
    async def simulate_mongodb_storage(self, analysis_result):
        """Simulate storing analysis results in MongoDB."""
        logger.info("💾 Storing analysis results in MongoDB...")
        await asyncio.sleep(0.5)
        
        # Simulate MongoDB document structure
        mongo_document = {
            "_id": analysis_result["analysis_id"],
            "session_id": self.session_id,
            "user": "vaibhav",
            "timestamp": analysis_result["timestamp"],
            "log_sources": ["security_events", "system_events", "process_monitor"],
            "analysis_data": analysis_result,
            "metadata": {
                "cli_version": "1.0.0",
                "extraction_method": "dynamic",
                "ai_agent_enabled": True,
                "storage_timestamp": datetime.utcnow().isoformat()
            }
        }
        
        logger.info(f"✅ Analysis stored in MongoDB with ID: {analysis_result['analysis_id']}")
        logger.info(f"   Collection: analysis_results")
        logger.info(f"   Document size: {len(json.dumps(mongo_document))} bytes")
        
        return mongo_document
    
    async def simulate_monitoring_cycle(self):
        """Simulate one complete monitoring cycle."""
        cycle_start = datetime.utcnow()
        logger.info(f"🔄 Starting monitoring cycle at {cycle_start.strftime('%H:%M:%S')}")
        
        try:
            # Step 1: Extract dynamic logs
            logs = await self.simulate_dynamic_log_extraction()
            
            # Step 2: Analyze with AI
            analysis_result = await self.simulate_ai_analysis(logs)
            
            # Step 3: Store in MongoDB
            mongo_doc = await self.simulate_mongodb_storage(analysis_result)
            
            # Step 4: Update monitoring session
            cycle_end = datetime.utcnow()
            cycle_duration = (cycle_end - cycle_start).total_seconds()
            
            logger.info(f"✅ Monitoring cycle completed in {cycle_duration:.2f} seconds")
            logger.info(f"   Next cycle in 5 minutes...")
            
            return {
                "success": True,
                "cycle_duration": cycle_duration,
                "analysis_id": analysis_result["analysis_id"],
                "threat_level": analysis_result["ai_agent_analysis"]["threat_level"]
            }
            
        except Exception as e:
            logger.error(f"❌ Monitoring cycle failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def run_continuous_monitoring(self, duration_minutes=15):
        """Run continuous monitoring for a specified duration."""
        logger.info("🚀 Starting ForensIQ Dynamic Monitoring System")
        logger.info("=" * 60)
        logger.info(f"Session ID: {self.session_id}")
        logger.info(f"Monitoring Duration: {duration_minutes} minutes")
        logger.info(f"Cycle Interval: 5 minutes")
        logger.info("=" * 60)
        
        # Authenticate first
        await self.simulate_authentication()
        
        start_time = datetime.utcnow()
        end_time = start_time + timedelta(minutes=duration_minutes)
        cycle_count = 0
        successful_cycles = 0
        
        while datetime.utcnow() < end_time:
            cycle_count += 1
            logger.info(f"\n📍 CYCLE {cycle_count} - {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')}")
            logger.info("-" * 40)
            
            # Run monitoring cycle
            result = await self.simulate_monitoring_cycle()
            
            if result["success"]:
                successful_cycles += 1
                logger.info(f"✅ Cycle {cycle_count} successful - Threat Level: {result['threat_level'].upper()}")
            else:
                logger.error(f"❌ Cycle {cycle_count} failed: {result.get('error')}")
            
            # Wait for next cycle (5 minutes) or exit if duration exceeded
            next_cycle = datetime.utcnow() + timedelta(minutes=5)
            if next_cycle < end_time:
                logger.info(f"⏰ Waiting 5 minutes for next cycle...")
                await asyncio.sleep(300)  # 5 minutes
            else:
                break
        
        # Summary
        total_duration = (datetime.utcnow() - start_time).total_seconds() / 60
        logger.info("\n" + "=" * 60)
        logger.info("📊 MONITORING SESSION SUMMARY")
        logger.info("=" * 60)
        logger.info(f"Session ID: {self.session_id}")
        logger.info(f"Total Duration: {total_duration:.1f} minutes")
        logger.info(f"Total Cycles: {cycle_count}")
        logger.info(f"Successful Cycles: {successful_cycles}")
        logger.info(f"Success Rate: {(successful_cycles/cycle_count)*100:.1f}%")
        logger.info(f"Total Analyses: {self.analysis_count}")
        logger.info("✅ Monitoring session completed successfully!")

async def main():
    """Main demo function."""
    print("🔍 ForensIQ Dynamic Monitoring System Demo")
    print("This demo shows how the CLI tool automatically:")
    print("  1. Extracts logs dynamically from system sources")
    print("  2. Analyzes logs with AI every 5 minutes")
    print("  3. Stores results in MongoDB")
    print("  4. Provides continuous monitoring")
    print()
    
    demo = ForensIQMonitoringDemo()
    
    # Run for 15 minutes (3 cycles) for demonstration
    await demo.run_continuous_monitoring(duration_minutes=15)

if __name__ == "__main__":
    asyncio.run(main())
