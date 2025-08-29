#!/usr/bin/env python3
"""
ForensIQ CLI Tool - Automated Log Analysis Client

This CLI tool automates the process of sending logs to the ForensIQ API endpoints
with authentication, encryption, and scheduled intervals. It provides:
- One-time user authentication with token storage
- Encrypted log transmission
- Configurable intervals for log sending
- User profile management
- AI agent integration for enhanced analysis

Usage:
    python cli_tool.py auth login --username <username> --password <password>
    python cli_tool.py profile setup --log-path <path> --interval <seconds>
    python cli_tool.py send --file <log_file>
    python cli_tool.py monitor --start
    python cli_tool.py analyze --file <log_file> --enhanced
"""

import asyncio
import argparse
import json
import os
import sys
import time
import logging
import schedule
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List
import requests
import aiohttp
import aiofiles
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import hashlib
import getpass

# Import AI Agent and Dynamic Log Extractor
from ai_agent import AIAgent
from dynamic_log_extractor import DynamicLogExtractor
from mongodb_service import mongodb_service

# Configuration
DEFAULT_CONFIG_DIR = Path.home() / ".forensiq"
CONFIG_FILE = DEFAULT_CONFIG_DIR / "config.json"
CREDENTIALS_FILE = DEFAULT_CONFIG_DIR / "credentials.enc"
LOGS_CACHE = DEFAULT_CONFIG_DIR / "logs_cache"

class ForensIQCLI:
    """Main CLI class for ForensIQ automated log analysis."""
    
    def __init__(self):
        self.config_dir = DEFAULT_CONFIG_DIR
        self.config_file = CONFIG_FILE
        self.credentials_file = CREDENTIALS_FILE
        self.logs_cache = LOGS_CACHE
        self.config = {}
        self.session_token = None
        self.encryption_key = None
        self.logger = self._setup_logging()
        
        # Initialize AI Agent
        self.ai_agent = None
        
        # Ensure config directory exists
        self.config_dir.mkdir(exist_ok=True)
        self.logs_cache.mkdir(exist_ok=True)
        
        # Load existing configuration
        self._load_config()
        
        # Try to load stored credentials automatically
        self._auto_load_credentials()
        
        # Initialize AI agent after config is loaded
        if self.config.get('ai_agent_enabled', True):
            self.ai_agent = AIAgent(self)
            self.logger.info("AI Agent initialized")
        
        # Initialize MongoDB service
        try:
            self.mongodb_service = mongodb_service
            self.logger.info("MongoDB service initialized")
        except Exception as e:
            self.logger.warning(f"MongoDB service initialization failed: {e}")
            self.mongodb_service = None
        
        # Initialize dynamic log extractor
        try:
            self.dynamic_extractor = DynamicLogExtractor()
            self.log_extractor = self.dynamic_extractor  # Alias for compatibility
            self.logger.info("Dynamic log extractor initialized")
        except Exception as e:
            self.logger.warning(f"Dynamic log extractor initialization failed: {e}")
            self.dynamic_extractor = None
            self.log_extractor = None
    
    def _setup_logging(self) -> logging.Logger:
        """Setup logging configuration."""
        # Ensure the config directory exists
        self.config_dir.mkdir(parents=True, exist_ok=True)
        
        log_file = self.config_dir / "forensiq_cli.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler()
            ]
        )
        return logging.getLogger("ForensIQCLI")
    
    def _setup_directories(self):
        """Setup necessary directories for the CLI tool."""
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.logger.info(f"Config directory setup at: {self.config_dir}")
    
    def _generate_encryption_key(self, password: str) -> bytes:
        """Generate encryption key from password."""
        password = password.encode()
        salt = b'forensiq_salt_2024'  # In production, use random salt per user
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        return key
    
    def _encrypt_data(self, data: str, key: bytes) -> str:
        """Encrypt sensitive data."""
        f = Fernet(key)
        encrypted_data = f.encrypt(data.encode())
        return base64.urlsafe_b64encode(encrypted_data).decode()
    
    def _decrypt_data(self, encrypted_data: str, key: bytes) -> str:
        """Decrypt sensitive data."""
        f = Fernet(key)
        encrypted_bytes = base64.urlsafe_b64decode(encrypted_data.encode())
        decrypted_data = f.decrypt(encrypted_bytes)
        return decrypted_data.decode()
    
    def _load_config(self) -> None:
        """Load configuration from file."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r') as f:
                    self.config = json.load(f)
                self.logger.info("Configuration loaded successfully")
            except Exception as e:
                self.logger.error(f"Failed to load configuration: {e}")
                self.config = {}
    
    def _save_config(self) -> None:
        """Save configuration to file."""
        try:
            # Ensure the config directory exists
            self.config_dir.mkdir(parents=True, exist_ok=True)
            
            with open(self.config_file, 'w') as f:
                json.dump(self.config, f, indent=2)
            self.logger.info("Configuration saved successfully")
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
    
    def _save_credentials(self, username: str, token: str, password: str) -> None:
        """Save encrypted credentials."""
        try:
            self.encryption_key = self._generate_encryption_key(password)
            credentials = {
                'username': username,
                'token': token,
                'timestamp': datetime.utcnow().isoformat()
            }
            encrypted_creds = self._encrypt_data(json.dumps(credentials), self.encryption_key)
            
            with open(self.credentials_file, 'w') as f:
                f.write(encrypted_creds)
            self.logger.info("Credentials saved successfully")
        except Exception as e:
            self.logger.error(f"Failed to save credentials: {e}")
            raise
    
    def _load_credentials(self, password: str) -> Optional[Dict[str, Any]]:
        """Load and decrypt credentials."""
        if not self.credentials_file.exists():
            return None
        
        try:
            self.encryption_key = self._generate_encryption_key(password)
            
            with open(self.credentials_file, 'r') as f:
                encrypted_creds = f.read()
            
            decrypted_creds = self._decrypt_data(encrypted_creds, self.encryption_key)
            credentials = json.loads(decrypted_creds)
            
            # Check if token is still valid (24 hours)
            token_time = datetime.fromisoformat(credentials['timestamp'])
            if datetime.utcnow() - token_time > timedelta(hours=24):
                self.logger.warning("Stored token has expired")
                return None
            
            self.session_token = credentials['token']
            return credentials
        except Exception as e:
            self.logger.error(f"Failed to load credentials: {e}")
            return None
    
    def _auto_load_credentials(self) -> None:
        """Automatically load stored credentials if available."""
        if not self.credentials_file.exists():
            return
        
        # Get stored username from config
        stored_username = self.config.get('username')
        if not stored_username:
            return
        
        try:
            # Try to load credentials without password (we'll use a placeholder approach)
            with open(self.credentials_file, 'r') as f:
                encrypted_data = f.read()
            
            # Store encrypted data for later use
            self._stored_encrypted_credentials = encrypted_data
            self._stored_username = stored_username
            
            self.logger.debug(f"Found stored credentials for user: {stored_username}")
            
        except Exception as e:
            self.logger.debug(f"Could not load stored credentials: {e}")
    
    def _load_stored_token(self) -> bool:
        """Load stored token using the password from authentication."""
        if not hasattr(self, '_stored_encrypted_credentials'):
            return False
        
        try:
            if not self.encryption_key:
                return False
            
            decrypted_creds = self._decrypt_data(self._stored_encrypted_credentials, self.encryption_key)
            credentials = json.loads(decrypted_creds)
            
            # Check if token is still valid (24 hours)
            token_time = datetime.fromisoformat(credentials['timestamp'])
            if datetime.now(timezone.utc) - token_time > timedelta(hours=24):
                self.logger.warning("Stored token has expired")
                return False
            
            self.session_token = credentials['token']
            self.logger.info("Loaded stored authentication token")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to load stored token: {e}")
            return False
    
    async def authenticate(self, username: str, password: str, api_url: str = None) -> bool:
        """Authenticate user and store token."""
        api_url = api_url or self.config.get('api_url', 'http://localhost:8000')
        
        try:
            async with aiohttp.ClientSession() as session:
                login_data = {
                    'username': username,
                    'password': password
                }
                
                async with session.post(f"{api_url}/login", json=login_data) as response:
                    if response.status == 200:
                        result = await response.json()
                        token = result.get('access_token')
                        
                        if token:
                            self._save_credentials(username, token, password)
                            self.session_token = token
                            self.config['api_url'] = api_url
                            self.config['username'] = username
                            self._save_config()
                            self.logger.info(f"Authentication successful for user: {username}")
                            return True
                    else:
                        error_detail = await response.text()
                        self.logger.error(f"Authentication failed: {error_detail}")
                        return False
        except Exception as e:
            self.logger.error(f"Authentication error: {e}")
            return False
    
    async def register_user(self, username: str, email: str, password: str) -> bool:
        """
        Register a new user with the ForensIQ server.
        
        Args:
            username: Desired username
            email: User's email address
            password: User's password
            
        Returns:
            bool: True if registration successful, False otherwise
        """
        try:
            api_base = self.config.get('api_url', 'http://localhost:8000')
            register_url = f"{api_base}/register"
            
            # Prepare registration request
            user_data = {
                "username": username,
                "email": email,
                "password": password
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(register_url, json=user_data) as response:
                    if response.status == 200:
                        self.logger.info(f"Successfully registered user: {username}")
                        return True
                    else:
                        error_detail = await response.text()
                        self.logger.error(f"Registration failed: {response.status} - {error_detail}")
                        return False
                        
        except Exception as e:
            self.logger.error(f"Registration error: {e}")
            return False

    async def get_user_profile(self) -> Optional[Dict[str, Any]]:
        """
        Get current user's profile information.
        
        Returns:
            Dict containing user profile or None if failed
        """
        try:
            if not self.session_token:
                self.logger.error("No valid authentication token. Please login first.")
                return None
            
            api_base = self.config.get('api_url', 'http://localhost:8000')
            profile_url = f"{api_base}/users/me"
            
            headers = {
                'Authorization': f'Bearer {self.session_token}',
                'Content-Type': 'application/json'
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.get(profile_url, headers=headers) as response:
                    if response.status == 200:
                        profile = await response.json()
                        self.logger.info("Successfully retrieved user profile")
                        return profile
                    else:
                        self.logger.error(f"Failed to get profile: {response.status}")
                        return None
                        
        except Exception as e:
            self.logger.error(f"Profile retrieval error: {e}")
            return None

    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers for API requests."""
        if not self.session_token:
            return {}
        
        return {
            'Authorization': f'Bearer {self.session_token}',
            'Content-Type': 'application/json'
        }
    
    async def send_logs(self, log_content: str, enhance_with_ai: bool = True) -> Optional[Dict[str, Any]]:
        """
        Send logs to the ForensIQ analysis endpoint.
        
        Args:
            log_content: The log content to analyze
            enhance_with_ai: Whether to use AI enhancement
            
        Returns:
            Analysis results or None if failed
        """
        if not self.session_token:
            self.logger.error("No valid authentication token. Please login first.")
            return None
        
        api_url = self.config.get('api_url', 'http://localhost:8000')
        
        try:
            headers = self._get_auth_headers()
            
            request_data = {
                'logs': log_content,
                'enhance_with_ai': enhance_with_ai,
                'max_results': self.config.get('max_results', 5)
            }
            
            self.logger.info(f"Sending {len(log_content)} characters of logs for analysis")
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{api_url}/api/v1/analyze", 
                    json=request_data, 
                    headers=headers
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        self.logger.info(f"Analysis completed successfully")
                        
                        # Store analysis result in cache
                        await self._cache_analysis_result(log_content, result)
                        
                        return result
                    else:
                        error_detail = await response.text()
                        self.logger.error(f"Analysis failed: {response.status} - {error_detail}")
                        return None
                        
        except Exception as e:
            self.logger.error(f"Error sending logs: {e}")
            return None

    async def _cache_analysis_result(self, log_content: str, result: Dict[str, Any]) -> None:
        """Cache analysis result for future reference."""
        try:
            cache_dir = self.config_dir / "analysis_cache"
            cache_dir.mkdir(exist_ok=True)
            
            # Create a hash of the log content for the filename
            log_hash = hashlib.sha256(log_content.encode()).hexdigest()[:16]
            cache_file = cache_dir / f"analysis_{log_hash}.json"
            
            cache_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'log_content_hash': log_hash,
                'result': result,
                'user': self.config.get('username', 'unknown')
            }
            
            async with aiofiles.open(cache_file, 'w') as f:
                await f.write(json.dumps(cache_data, indent=2))
                
            self.logger.debug(f"Analysis result cached to {cache_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to cache analysis result: {e}")

    async def get_cached_analysis(self, log_content: str) -> Optional[Dict[str, Any]]:
        """Get cached analysis result if available."""
        try:
            cache_dir = self.config_dir / "analysis_cache"
            if not cache_dir.exists():
                return None
            
            log_hash = hashlib.sha256(log_content.encode()).hexdigest()[:16]
            cache_file = cache_dir / f"analysis_{log_hash}.json"
            
            if cache_file.exists():
                async with aiofiles.open(cache_file, 'r') as f:
                    cache_data = json.loads(await f.read())
                
                # Check if cache is still valid (e.g., less than 1 hour old)
                cache_time = datetime.fromisoformat(cache_data['timestamp'])
                if datetime.utcnow() - cache_time < timedelta(hours=1):
                    self.logger.info("Using cached analysis result")
                    return cache_data['result']
                    
        except Exception as e:
            self.logger.debug(f"Failed to retrieve cached analysis: {e}")
            
        return None

    async def send_logs_with_retry(self, log_content: str, enhance_with_ai: bool = True, max_retries: int = 3) -> Optional[Dict[str, Any]]:
        """
        Send logs with retry logic and caching.
        
        Args:
            log_content: The log content to analyze  
            enhance_with_ai: Whether to use AI enhancement
            max_retries: Maximum number of retry attempts
            
        Returns:
            Analysis results or None if failed
        """
        # Check cache first
        cached_result = await self.get_cached_analysis(log_content)
        if cached_result:
            return cached_result
        
        # Try sending logs with retries
        for attempt in range(max_retries):
            try:
                result = await self.send_logs(log_content, enhance_with_ai)
                if result:
                    return result
                
                # If authentication failed, try to refresh token
                if attempt < max_retries - 1:
                    self.logger.warning(f"Attempt {attempt + 1} failed, retrying...")
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    
            except Exception as e:
                self.logger.error(f"Attempt {attempt + 1} failed: {e}")
                if attempt < max_retries - 1:
                    await asyncio.sleep(2 ** attempt)
        
        return None
    
    async def send_log_file(self, file_path: str, enhance_with_ai: bool = True, use_ai_agent: bool = True) -> Optional[Dict[str, Any]]:
        """Send log file for analysis with optional AI agent enhancement."""
        try:
            async with aiofiles.open(file_path, 'r', encoding='utf-8') as f:
                log_content = await f.read()
            
            # Limit log size to 50KB as per API constraints
            if len(log_content) > 50000:
                self.logger.warning("Log file too large, truncating to 50KB")
                log_content = log_content[:50000]
            
            # Use AI agent for enhanced analysis if available and enabled
            if use_ai_agent and self.ai_agent:
                self.logger.info("Using AI Agent for enhanced analysis")
                result = await self.ai_agent.enhanced_analysis(log_content)
            else:
                self.logger.info("Using standard API analysis")
                result = await self.send_logs(log_content, enhance_with_ai)
            
            if result:
                # Save result to cache
                timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
                result_file = self.logs_cache / f"analysis_{timestamp}.json"
                async with aiofiles.open(result_file, 'w') as f:
                    await f.write(json.dumps(result, indent=2, default=str))
                self.logger.info(f"Analysis result saved to: {result_file}")
                
                # Update adaptive scheduling if AI agent is used
                if use_ai_agent and self.ai_agent and 'ai_agent_analysis' in result:
                    adaptive_config = result['ai_agent_analysis'].get('adaptive_scheduling', {})
                    if 'next_interval' in adaptive_config:
                        self.config['adaptive_interval'] = adaptive_config['next_interval']
                        self._save_config()
                        self.logger.info(f"Updated adaptive interval: {adaptive_config['next_interval']}s")
            
            return result
        except Exception as e:
            self.logger.error(f"Error reading log file {file_path}: {e}")
            return None
    
    async def setup_dynamic_monitoring(self, sources: List[str] = None, interval: int = 300, 
                                     auto_enhance: bool = True, enable_ai_agent: bool = True) -> bool:
        """
        Setup dynamic monitoring profile that extracts logs from system sources.
        
        Args:
            sources: List of log sources to monitor (None for all available)
            interval: Monitoring interval in seconds (default 5 minutes)
            auto_enhance: Enable AI enhancement by default
            enable_ai_agent: Enable AI agent for adaptive scheduling
            
        Returns:
            bool: True if profile setup successful
        """
        try:
            # Test API connection
            profile = await self.get_user_profile()
            if not profile:
                self.logger.error("Cannot setup dynamic monitoring without valid authentication")
                return False
            
            # Get available log sources
            available_sources = self.log_extractor.get_available_sources()
            
            if not available_sources:
                self.logger.error("No log sources available on this system")
                return False
            
            # Use all available sources if none specified
            if sources is None:
                sources = [source['id'] for source in available_sources]
            else:
                # Validate specified sources
                available_ids = [source['id'] for source in available_sources]
                invalid_sources = [s for s in sources if s not in available_ids]
                if invalid_sources:
                    self.logger.error(f"Invalid log sources: {invalid_sources}")
                    self.logger.info(f"Available sources: {available_ids}")
                    return False
            
            # Update configuration for dynamic monitoring
            self.config.update({
                'dynamic_monitoring': {
                    'enabled': True,
                    'sources': sources,
                    'interval': interval,
                    'auto_enhance': auto_enhance,
                    'enable_ai_agent': enable_ai_agent,
                    'extraction_time_range': 5  # Extract logs from last 5 minutes
                },
                'profile_user': profile.get('username'),
                'profile_email': profile.get('email'),
                'profile_created': datetime.utcnow().isoformat(),
                'monitoring_type': 'dynamic'
            })
            
            # Initialize AI agent if enabled
            if enable_ai_agent and not self.ai_agent:
                self.ai_agent = AIAgent(self)
                self.config['ai_agent_enabled'] = True
            
            self._save_config()
            
            # Create monitoring directory structure
            monitor_dir = self.config_dir / "dynamic_monitoring"
            monitor_dir.mkdir(exist_ok=True)
            
            # Save monitoring metadata
            monitoring_metadata = {
                'sources': sources,
                'available_sources': available_sources,
                'interval': interval,
                'user': profile.get('username'),
                'created': datetime.utcnow().isoformat(),
                'system_info': self.log_extractor.get_system_summary()
            }
            
            async with aiofiles.open(monitor_dir / "metadata.json", 'w') as f:
                await f.write(json.dumps(monitoring_metadata, indent=2))
            
            self.logger.info(f"Dynamic monitoring profile configured successfully")
            self.logger.info(f"  Sources: {', '.join(sources)}")
            self.logger.info(f"  Interval: {interval} seconds")
            self.logger.info(f"  AI Agent: {'Enabled' if enable_ai_agent else 'Disabled'}")
            self.logger.info(f"  Available sources: {len(available_sources)}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup dynamic monitoring: {e}")
            return False

    def get_available_log_sources(self) -> List[Dict[str, Any]]:
        """Get list of available log sources for the current system."""
        return self.log_extractor.get_available_sources()

    async def extract_and_send_logs(self, sources: List[str] = None, time_range_minutes: int = 5) -> Optional[Dict[str, Any]]:
        """Extract logs dynamically and send them for analysis.
        
        Args:
            sources: List of source IDs to extract from (None for configured sources)
            time_range_minutes: Extract logs from last N minutes
            
        Returns:
            Analysis results or None if failed
        """
        try:
            if not self.session_token:
                self.logger.error("No valid authentication token. Please login first.")
                return None
            
            # Use configured sources if none specified
            if sources is None:
                dynamic_config = self.config.get('dynamic_monitoring', {})
                sources = dynamic_config.get('sources', [])
                if not sources:
                    self.logger.error("No sources configured for dynamic monitoring")
                    return None
            
            # Extract logs from system
            self.logger.info(f"Extracting logs from sources: {', '.join(sources)}")
            extracted_logs = self.log_extractor.extract_logs(sources, time_range_minutes)
            
            # Check if any logs were extracted
            total_logs = sum(len(logs) for logs in extracted_logs.values())
            if total_logs == 0:
                self.logger.info("No new logs found to analyze")
                return None
            
            # Format logs for analysis
            formatted_logs = self.log_extractor.format_logs_for_analysis(extracted_logs)
            
            if not formatted_logs.strip():
                self.logger.info("No substantive log content to analyze")
                return None
            
            self.logger.info(f"Sending {len(formatted_logs)} characters of dynamic logs for analysis")
            
            # Send to ForensIQ API for analysis
            enhance_with_ai = self.config.get('dynamic_monitoring', {}).get('auto_enhance', True)
            result = await self.send_logs(formatted_logs, enhance_with_ai)
            
            if result:
                # Add extraction metadata to result
                result['extraction_metadata'] = {
                    'sources_used': sources,
                    'total_log_entries': total_logs,
                    'extraction_details': {source: len(logs) for source, logs in extracted_logs.items()},
                    'time_range_minutes': time_range_minutes,
                    'extraction_time': datetime.utcnow().isoformat(),
                    'system_info': self.log_extractor.get_system_summary()
                }
                
                # Cache the result with extraction metadata
                await self._cache_dynamic_analysis_result(extracted_logs, result)
                
                self.logger.info("Dynamic log analysis completed successfully")
                return result
            else:
                self.logger.error("Failed to analyze extracted logs")
                return None
                
        except Exception as e:
            self.logger.error(f"Error in dynamic log extraction and analysis: {e}")
            return None

    async def _cache_dynamic_analysis_result(self, extracted_logs: Dict[str, List[Dict[str, Any]]], 
                                           result: Dict[str, Any]) -> None:
        """Cache dynamic analysis result with extraction details."""
        try:
            cache_dir = self.config_dir / "dynamic_analysis_cache"
            cache_dir.mkdir(exist_ok=True)
            
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            cache_file = cache_dir / f"dynamic_analysis_{timestamp}.json"
            
            cache_data = {
                'timestamp': datetime.utcnow().isoformat(),
                'extracted_logs': extracted_logs,
                'analysis_result': result,
                'user': self.config.get('profile_user', 'unknown')
            }
            
            async with aiofiles.open(cache_file, 'w') as f:
                await f.write(json.dumps(cache_data, indent=2, default=str))
                
            self.logger.debug(f"Dynamic analysis result cached to {cache_file}")
            
        except Exception as e:
            self.logger.error(f"Failed to cache dynamic analysis result: {e}")

    async def start_dynamic_monitoring(self) -> None:
        """Start dynamic monitoring with configured settings and real MongoDB storage."""
        dynamic_config = self.config.get('dynamic_monitoring', {})
        
        if not dynamic_config.get('enabled'):
            self.logger.error("Dynamic monitoring not configured. Use 'profile setup-dynamic' first.")
            return
        
        sources = dynamic_config.get('sources', [])
        base_interval = dynamic_config.get('interval', 300)  # Default 5 minutes
        time_range = dynamic_config.get('extraction_time_range', 5)
        username = self.config.get('username', 'unknown')
        
        # Connect to MongoDB
        if self.mongodb_service:
            try:
                mongodb_connected = await self.mongodb_service.connect_async()
                if not mongodb_connected:
                    self.logger.warning("Failed to connect to MongoDB. Data will not be stored.")
            except Exception as e:
                self.logger.warning(f"MongoDB connection error: {e}")
        else:
            self.logger.warning("MongoDB service not available. Data will not be stored.")
        
        # Create monitoring session in MongoDB
        session_id = None
        if self.mongodb_service:
            session_id = await self.mongodb_service.create_monitoring_session(
                username=username,
                log_sources=sources,
                interval=base_interval
            )
        
        self.logger.info(f"Starting dynamic monitoring...")
        self.logger.info(f"  Session ID: {session_id}")
        self.logger.info(f"  Sources: {', '.join(sources)}")
        self.logger.info(f"  Base interval: {base_interval} seconds")
        self.logger.info(f"  Extraction time range: {time_range} minutes")
        self.logger.info(f"  MongoDB storage: ENABLED")
        
        monitoring_start_time = datetime.utcnow()
        analysis_count = 0
        
        try:
            while True:
                cycle_start = time.time()
                
                try:
                    # Extract and analyze logs
                    result = await self.extract_and_send_logs(sources, time_range)
                    
                    if result:
                        analysis_count += 1
                        
                        # Store result in MongoDB in real-time
                        if self.mongodb_service and session_id:
                            try:
                                analysis_id = await self.mongodb_service.store_analysis_result_with_session(
                                    analysis_data=result,
                                    username=username,
                                    session_id=session_id
                                )
                                
                                # Update monitoring session stats
                                await self.mongodb_service.update_monitoring_session(
                                    session_id=session_id,
                                    total_analyses=analysis_count,
                                    last_analysis=datetime.utcnow()
                                )
                                
                                self.logger.info(f"✓ Analysis #{analysis_count} stored in MongoDB (ID: {analysis_id})")
                                
                            except Exception as e:
                                self.logger.error(f"Failed to store analysis in MongoDB: {e}")
                        else:
                            self.logger.debug(f"✓ Analysis #{analysis_count} completed (MongoDB storage unavailable)")
                        
                        # Display summary
                        metadata = result.get('extraction_metadata', {})
                        print(f"\n🔍 Dynamic Analysis Complete [{datetime.now().strftime('%H:%M:%S')}]")
                        if session_id:
                            print(f"  📊 Analysis #{analysis_count}")
                            print(f"  📝 Session ID: {session_id}")
                        print(f"  📋 Extracted: {metadata.get('total_log_entries', 0)} log entries")
                        print(f"  🎯 Sources: {', '.join(metadata.get('sources_used', []))}")
                        print(f"  💾 Stored in MongoDB: ✅")
                        
                        if 'matched_techniques' in result:
                            techniques = result['matched_techniques']
                            print(f"  MITRE Techniques: {len(techniques)}")
                            for tech in techniques[:3]:  # Show top 3
                                print(f"    - {tech.get('technique_id')}: {tech.get('name')} (Score: {tech.get('relevance_score', 0):.2f})")
                        
                        # Adaptive scheduling with AI agent
                        if self.ai_agent:
                            # Use AI agent for enhanced analysis and adaptive scheduling
                            enhanced_result = await self.ai_agent.enhanced_analysis_for_dynamic_logs(result, sources)
                            
                            # Get adaptive interval
                            next_interval = self.ai_agent.adaptive_schedule_analysis(enhanced_result.get('threat_context'))
                            if next_interval != base_interval:
                                print(f"  AI Agent: Adjusted interval to {next_interval}s based on threat level")
                                base_interval = next_interval
                    else:
                        print(f"⏱️  No new logs to analyze [{datetime.now().strftime('%H:%M:%S')}]\n")
                    
                except Exception as e:
                    self.logger.error(f"Error in monitoring cycle: {e}")
                    print(f"❌ Monitoring cycle error: {e}")
                
                # Calculate sleep time
                cycle_duration = time.time() - cycle_start
                sleep_time = max(base_interval - cycle_duration, 10)  # Minimum 10 seconds
                
                print(f"⏳ Next extraction in {sleep_time:.0f} seconds...")
                await asyncio.sleep(sleep_time)
                
        except KeyboardInterrupt:
            monitoring_duration = datetime.utcnow() - monitoring_start_time
            print(f"\n🛑 Dynamic monitoring stopped (ran for {monitoring_duration})\n")
            self.logger.info("Dynamic monitoring stopped by user")
        except Exception as e:
            self.logger.error(f"Dynamic monitoring error: {e}")
            print(f"❌ Dynamic monitoring error: {e}")
    
    async def setup_monitoring_profile(self, log_path: str, interval: int, max_results: int = 5, 
                                     auto_enhance: bool = True, enable_ai_agent: bool = True) -> bool:
        """
        Setup comprehensive monitoring profile with server integration.
        
        Args:
            log_path: Path to the log file to monitor
            interval: Monitoring interval in seconds  
            max_results: Maximum MITRE techniques to return
            auto_enhance: Enable AI enhancement by default
            enable_ai_agent: Enable AI agent for adaptive scheduling
            
        Returns:
            bool: True if profile setup successful
        """
        try:
            # Validate log file exists and is readable
            if not Path(log_path).exists():
                self.logger.error(f"Log file does not exist: {log_path}")
                return False
                
            if not os.access(log_path, os.R_OK):
                self.logger.error(f"Cannot read log file: {log_path}")
                return False
            
            # Test API connection
            profile = await self.get_user_profile()
            if not profile:
                self.logger.error("Cannot setup profile without valid authentication")
                return False
            
            # Update configuration
            self.config.update({
                'monitoring': {
                    'log_path': str(Path(log_path).absolute()),
                    'interval': interval,
                    'max_results': max_results,
                    'auto_enhance': auto_enhance,
                    'enable_ai_agent': enable_ai_agent
                },
                'profile_user': profile.get('username'),
                'profile_email': profile.get('email'),
                'profile_created': datetime.utcnow().isoformat(),
                'last_file_position': 0  # Track file position for incremental reading
            })
            
            # Initialize AI agent if enabled
            if enable_ai_agent and not self.ai_agent:
                self.ai_agent = AIAgent(self)
                self.config['ai_agent_enabled'] = True
            
            self._save_config()
            
            # Create monitoring directory structure
            monitor_dir = self.config_dir / "monitoring"
            monitor_dir.mkdir(exist_ok=True)
            
            # Save profile metadata
            profile_metadata = {
                'log_path': log_path,
                'interval': interval,
                'user': profile.get('username'),
                'created': datetime.utcnow().isoformat(),
                'file_size': Path(log_path).stat().st_size,
                'file_modified': datetime.fromtimestamp(Path(log_path).stat().st_mtime).isoformat()
            }
            
            async with aiofiles.open(monitor_dir / "profile.json", 'w') as f:
                await f.write(json.dumps(profile_metadata, indent=2))
            
            self.logger.info(f"Monitoring profile configured successfully")
            self.logger.info(f"  Log file: {log_path}")
            self.logger.info(f"  Interval: {interval} seconds")
            self.logger.info(f"  AI Agent: {'Enabled' if enable_ai_agent else 'Disabled'}")
            
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to setup monitoring profile: {e}")
            return False

    async def get_profile_status(self) -> Dict[str, Any]:
        """
        Get current profile status and monitoring information.
        
        Returns:
            Dict containing profile status information
        """
        try:
            monitoring_config = self.config.get('monitoring', {})
            
            if not monitoring_config:
                return {'status': 'not_configured', 'message': 'No monitoring profile configured'}
            
            log_path = monitoring_config.get('log_path')
            status = {
                'status': 'active',
                'log_path': log_path,
                'interval': monitoring_config.get('interval'),
                'max_results': monitoring_config.get('max_results'),
                'auto_enhance': monitoring_config.get('auto_enhance'),
                'ai_agent_enabled': monitoring_config.get('enable_ai_agent'),
                'user': self.config.get('profile_user'),
                'email': self.config.get('profile_email'),
                'created': self.config.get('profile_created')
            }
            
            # Check log file status
            if log_path and Path(log_path).exists():
                file_stat = Path(log_path).stat()
                status.update({
                    'log_file_size': file_stat.st_size,
                    'log_file_modified': datetime.fromtimestamp(file_stat.st_mtime).isoformat(),
                    'log_file_accessible': os.access(log_path, os.R_OK)
                })
            else:
                status['log_file_exists'] = False
                status['status'] = 'error'
                status['message'] = 'Configured log file not found'
            
            # Get AI agent status if available
            if self.ai_agent:
                agent_status = self.ai_agent.get_agent_status()
                status['ai_agent_status'] = agent_status
            
            return status
            
        except Exception as e:
            self.logger.error(f"Failed to get profile status: {e}")
            return {'status': 'error', 'message': str(e)}

    async def update_profile_settings(self, **kwargs) -> bool:
        """
        Update specific profile settings.
        
        Args:
            **kwargs: Profile settings to update
            
        Returns:
            bool: True if update successful
        """
        try:
            monitoring_config = self.config.get('monitoring', {})
            
            # Update monitoring configuration
            for key, value in kwargs.items():
                if key in ['interval', 'max_results', 'auto_enhance', 'enable_ai_agent']:
                    monitoring_config[key] = value
                    self.logger.info(f"Updated {key} to {value}")
            
            self.config['monitoring'] = monitoring_config
            self.config['profile_updated'] = datetime.utcnow().isoformat()
            
            # Handle AI agent enable/disable
            if 'enable_ai_agent' in kwargs:
                if kwargs['enable_ai_agent'] and not self.ai_agent:
                    self.ai_agent = AIAgent(self)
                    self.config['ai_agent_enabled'] = True
                elif not kwargs['enable_ai_agent']:
                    self.ai_agent = None
                    self.config['ai_agent_enabled'] = False
            
            self._save_config()
            self.logger.info("Profile settings updated successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to update profile settings: {e}")
            return False
    
    async def retrieve_analysis_data(self, limit: int = 10, user_filter: str = None) -> List[Dict[str, Any]]:
        """
        Retrieve analysis data directly from MongoDB.
        
        Args:
            limit: Maximum number of records to retrieve
            user_filter: Filter by specific username
            
        Returns:
            List of analysis records
        """
        try:
            if not self.mongodb_service:
                return []
            
            # Get current user if no filter specified
            username = user_filter or self.config.get('username')
            
            # Retrieve data from MongoDB
            results = await self.mongodb_service.get_analysis_results(
                limit=limit,
                user=username
            )
            
            self.logger.info(f"Retrieved {len(results)} analysis records from MongoDB")
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to retrieve analysis data: {e}")
            return []

    async def retrieve_monitoring_sessions(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Retrieve monitoring session data directly from MongoDB.
        
        Args:
            limit: Maximum number of records to retrieve
            
        Returns:
            List of monitoring session records
        """
        try:
            if not self.mongodb_service:
                return []
            
            username = self.config.get('username')
            
            # Retrieve sessions from MongoDB
            sessions = await self.mongodb_service.get_monitoring_sessions(
                limit=limit,
                user=username
            )
            
            self.logger.info(f"Retrieved {len(sessions)} monitoring sessions from MongoDB")
            return sessions
            
        except Exception as e:
            self.logger.error(f"Error retrieving monitoring sessions: {e}")
            return []

    async def get_collection_stats(self) -> Dict[str, Any]:
        """
        Get statistics about MongoDB collections.
        
        Returns:
            Dictionary containing collection statistics
        """
        try:
            if not self.mongodb_service:
                return {
                    'error': 'MongoDB service not available',
                    'connection_status': 'unavailable'
                }
            
            # Get statistics from MongoDB
            stats = await self.mongodb_service.get_collection_stats()
            
            self.logger.info("Retrieved collection statistics from MongoDB")
            return stats
            
        except Exception as e:
            self.logger.error(f"Error retrieving collection stats: {e}")
            return {
                'error': str(e),
                'connection_status': 'failed'
            }

    def display_analysis_data(self, data: List[Dict[str, Any]]) -> None:
        """Display analysis data in a formatted way."""
        if not data:
            print("No analysis data found.")
            return
        
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

    def display_monitoring_sessions(self, sessions: List[Dict[str, Any]]) -> None:
        """Display monitoring sessions in a formatted way."""
        if not sessions:
            print("No monitoring sessions found.")
            return
        
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

    def display_collection_stats(self, stats: Dict[str, Any]) -> None:
        """Display collection statistics in a formatted way."""
        if not stats:
            print("No statistics available.")
            return
        
        print("\n📈 MongoDB Collection Statistics:")
        print("=" * 50)
        
        for collection, data in stats.items():
            if isinstance(data, dict):
                print(f"\n🗃️  {collection.replace('_', ' ').title()}:")
                print(f"   Total Records: {data.get('count', 0):,}")
                print(f"   Storage Size: {data.get('size', 0):,} bytes")
                if data.get('last_updated'):
                    print(f"   Last Updated: {data.get('last_updated')}")

    async def export_collection_data(self, collection_type: str, output_file: str, 
                                   limit: int = None, format_type: str = 'json') -> bool:
        """
        Export collection data to a file.
        
        Args:
            collection_type: Type of collection ('analysis' or 'monitoring')
            output_file: Output file path
            limit: Maximum records to export
            format_type: Export format ('json' or 'csv')
            
        Returns:
            bool: True if export successful
        """
        try:
            if collection_type == 'analysis':
                data = await self.retrieve_analysis_data(limit or 1000)
            elif collection_type == 'monitoring':
                data = await self.retrieve_monitoring_sessions(limit or 1000)
            else:
                self.logger.error(f"Invalid collection type: {collection_type}")
                return False
            
            if not data:
                self.logger.warning("No data to export")
                return False
            
            if format_type == 'json':
                import json
                with open(output_file, 'w') as f:
                    json.dump(data, f, indent=2, default=str)
            elif format_type == 'csv':
                import csv
                if data:
                    with open(output_file, 'w', newline='') as f:
                        writer = csv.DictWriter(f, fieldnames=data[0].keys())
                        writer.writeheader()
                        for row in data:
                            # Convert complex fields to strings
                            csv_row = {}
                            for k, v in row.items():
                                if isinstance(v, (list, dict)):
                                    csv_row[k] = str(v)
                                else:
                                    csv_row[k] = v
                            writer.writerow(csv_row)
            
            self.logger.info(f"Exported {len(data)} records to {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Error exporting data: {e}")
            return False
    
    def setup_profile(self, log_path: str, interval: int, max_results: int = 5, auto_enhance: bool = True) -> None:
        """Setup user profile with monitoring configuration."""
        self.config.update({
            'log_path': log_path,
            'monitor_interval': interval,
            'max_results': max_results,
            'auto_enhance': auto_enhance,
            'profile_updated': datetime.utcnow().isoformat()
        })
        self._save_config()
        self.logger.info(f"Profile configured: log_path={log_path}, interval={interval}s")
    
    async def monitor_logs(self) -> None:
        """Monitor log file and send updates at configured intervals with MongoDB storage."""
        log_path = self.config.get('monitoring', {}).get('log_path')
        base_interval = self.config.get('monitoring', {}).get('interval', 300)  # Default 5 minutes
        
        if not log_path or not os.path.exists(log_path):
            self.logger.error(f"Log file not found: {log_path}")
            return
        
        # Create monitoring session in database
        session_id = await self._create_monitoring_session(log_path, base_interval)
        if not session_id:
            self.logger.error("Failed to create monitoring session")
            return
        
        self.logger.info(f"Starting log monitoring session: {session_id}")
        self.logger.info(f"Log file: {log_path}")
        self.logger.info(f"Base interval: {base_interval} seconds")
        
        last_position = self.config.get('last_file_position', 0)
        consecutive_errors = 0
        max_errors = 5
        
        try:
            while True:
                try:
                    # Check if file still exists
                    if not os.path.exists(log_path):
                        self.logger.error(f"Log file disappeared: {log_path}")
                        break
                    
                    # Read new content from file
                    current_size = os.path.getsize(log_path)
                    
                    if current_size > last_position:
                        # Read new content
                        with open(log_path, 'r', encoding='utf-8', errors='ignore') as f:
                            f.seek(last_position)
                            new_content = f.read()
                        
                        if new_content.strip():
                            self.logger.info(f"Processing {len(new_content)} new characters from log")
                            
                            # Analyze logs with AI agent enhancement
                            result = await self.analyze_logs_with_storage(
                                new_content, 
                                session_id=session_id,
                                log_file_path=log_path
                            )
                            
                            if result:
                                # Update file position
                                last_position = current_size
                                self.config['last_file_position'] = last_position
                                self._save_config()
                                
                                # Reset error counter on success
                                consecutive_errors = 0
                                
                                # Log successful analysis
                                self.logger.info(f"Analysis completed and stored in MongoDB")
                                
                                # Determine next interval based on AI agent feedback
                                next_interval = base_interval
                                if result.get('ai_agent_analysis'):
                                    ai_analysis = result['ai_agent_analysis']
                                    adaptive_scheduling = ai_analysis.get('adaptive_scheduling', {})
                                    next_interval = adaptive_scheduling.get('next_interval', base_interval)
                                    
                                    threat_level = ai_analysis.get('threat_context', {}).get('severity_level', 'low')
                                    self.logger.info(f"Threat level: {threat_level}, next interval: {next_interval}s")
                                
                                # Wait for next interval
                                await asyncio.sleep(next_interval)
                            else:
                                consecutive_errors += 1
                                self.logger.error(f"Analysis failed (error {consecutive_errors}/{max_errors})")
                                await asyncio.sleep(base_interval)
                        else:
                            # No new content, wait shorter interval
                            await asyncio.sleep(min(base_interval, 60))
                    
                    elif current_size < last_position:
                        # File was truncated or rotated
                        self.logger.info("Log file was truncated or rotated, resetting position")
                        last_position = 0
                        self.config['last_file_position'] = 0
                        self._save_config()
                        await asyncio.sleep(5)
                    else:
                        # No new content
                        await asyncio.sleep(min(base_interval, 60))
                
                except Exception as e:
                    consecutive_errors += 1
                    self.logger.error(f"Error during monitoring (attempt {consecutive_errors}/{max_errors}): {e}")
                    
                    if consecutive_errors >= max_errors:
                        self.logger.error("Too many consecutive errors, stopping monitoring")
                        break
                    
                    # Wait before retry with exponential backoff
                    wait_time = min(base_interval * (2 ** (consecutive_errors - 1)), 300)
                    await asyncio.sleep(wait_time)
        
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
        except Exception as e:
            self.logger.error(f"Fatal error in monitoring: {e}")
        finally:
            # Stop monitoring session in database
            await self._stop_monitoring_session(session_id)
            self.logger.info("Monitoring session ended")

    async def _create_monitoring_session(self, log_path: str, interval: int) -> Optional[str]:
        """Create monitoring session in the database."""
        try:
            if not self.session_token:
                self.logger.error("No authentication token available")
                return None
            
            api_url = self.config.get('api_url', 'http://localhost:8000')
            headers = self._get_auth_headers()
            
            session_data = {
                'log_path': log_path,
                'interval_seconds': interval,
                'ai_agent_enabled': self.config.get('ai_agent_enabled', True)
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{api_url}/api/v1/monitoring/sessions",
                    json=session_data,
                    headers=headers
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        return result.get('session_id')
                    else:
                        self.logger.error(f"Failed to create monitoring session: {response.status}")
                        return None
        except Exception as e:
            self.logger.error(f"Error creating monitoring session: {e}")
            return None
    
    async def _stop_monitoring_session(self, session_id: str) -> None:
        """Stop monitoring session in the database."""
        try:
            if not self.session_token:
                return
            
            api_url = self.config.get('api_url', 'http://localhost:8000')
            headers = self._get_auth_headers()
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{api_url}/api/v1/monitoring/sessions/{session_id}/stop",
                    headers=headers
                ) as response:
                    if response.status == 200:
                        self.logger.info("Monitoring session stopped successfully")
                    else:
                        self.logger.warning(f"Failed to stop monitoring session: {response.status}")
        except Exception as e:
            self.logger.error(f"Error stopping monitoring session: {e}")

    async def analyze_logs_with_storage(self, log_content: str, session_id: Optional[str] = None, 
                                      log_file_path: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """
        Analyze logs and store results in MongoDB.
        
        Args:
            log_content: Log content to analyze
            session_id: Associated monitoring session ID
            log_file_path: Path to the log file
            
        Returns:
            Analysis result or None if failed
        """
        try:
            # Use AI agent for enhanced analysis if available
            if self.ai_agent:
                result = await self.ai_agent.enhanced_analysis(log_content)
            else:
                result = await self.send_logs(log_content, enhance_with_ai=True)
            
            if result:
                # Store in MongoDB via API
                await self._store_analysis_result(result, log_content, session_id, log_file_path)
                return result
            
            return None
            
        except Exception as e:
            self.logger.error(f"Error in analyze_logs_with_storage: {e}")
            return None
    
    async def _store_analysis_result(self, analysis_result: Dict[str, Any], log_content: str,
                                   session_id: Optional[str] = None, log_file_path: Optional[str] = None) -> None:
        """Store analysis result in MongoDB via API."""
        try:
            if not self.session_token:
                return
            
            api_url = self.config.get('api_url', 'http://localhost:8000')
            headers = self._get_auth_headers()
            
            storage_data = {
                'log_content': log_content,
                'analysis_result': analysis_result,
                'session_id': session_id,
                'log_file_path': log_file_path
            }
            
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    f"{api_url}/api/v1/analysis/store",
                    json=storage_data,
                    headers=headers
                ) as response:
                    if response.status == 200:
                        result = await response.json()
                        self.logger.debug(f"Analysis stored with ID: {result.get('analysis_id')}")
                    else:
                        self.logger.warning(f"Failed to store analysis: {response.status}")
                        
        except Exception as e:
            self.logger.error(f"Error storing analysis result: {e}")

    async def start_background_monitoring(self) -> None:
        """Start background monitoring with 5-minute intervals."""
        monitoring_config = self.config.get('monitoring', {})
        
        if not monitoring_config:
            self.logger.error("No monitoring configuration found. Please setup profile first.")
            return
        
        log_path = monitoring_config.get('log_path')
        interval = monitoring_config.get('interval', 300)  # Default 5 minutes
        
        if not log_path or not os.path.exists(log_path):
            self.logger.error(f"Log file not found: {log_path}")
            return
        
        self.logger.info(f"Starting background monitoring with {interval} second intervals")
        self.logger.info(f"Monitoring file: {log_path}")
        self.logger.info("Press Ctrl+C to stop monitoring")
        
        try:
            await self.monitor_logs()
        except KeyboardInterrupt:
            self.logger.info("Monitoring stopped by user")
        except Exception as e:
            self.logger.error(f"Monitoring error: {e}")
    
    def schedule_analysis(self, cron_expression: str = None) -> None:
        """Schedule periodic log analysis using schedule library."""
        interval = self.config.get('monitor_interval', 300)
        log_path = self.config.get('log_path')
        
        if not log_path:
            self.logger.error("Log path not configured")
            return
        
        def run_analysis():
            """Run scheduled analysis."""
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                result = loop.run_until_complete(self.send_log_file(log_path))
                if result:
                    self.logger.info("Scheduled analysis completed successfully")
            except Exception as e:
                self.logger.error(f"Scheduled analysis failed: {e}")
            finally:
                loop.close()
        
        # Schedule based on interval
        schedule.every(interval).seconds.do(run_analysis)
        
        self.logger.info(f"Scheduled analysis every {interval} seconds")
        
        try:
            while True:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            self.logger.info("Scheduler stopped by user")

def main():
    """Main CLI entry point."""
    parser = argparse.ArgumentParser(description="ForensIQ CLI Tool for Automated Log Analysis")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Authentication commands
    auth_parser = subparsers.add_parser('auth', help='Authentication commands')
    auth_subparsers = auth_parser.add_subparsers(dest='auth_command')
    
    login_parser = auth_subparsers.add_parser('login', help='Login to ForensIQ')
    login_parser.add_argument('--username', required=True, help='Username')
    login_parser.add_argument('--password', help='Password (will prompt if not provided)')
    login_parser.add_argument('--api-url', default='http://localhost:8000', help='API URL')
    
    register_parser = auth_subparsers.add_parser('register', help='Register new user')
    register_parser.add_argument('--username', required=True, help='Desired username')
    register_parser.add_argument('--email', required=True, help='Email address')
    register_parser.add_argument('--password', help='Password (will prompt if not provided)')
    
    profile_cmd_parser = auth_subparsers.add_parser('profile', help='Get user profile')
    
    # Profile commands
    profile_parser = subparsers.add_parser('profile', help='Profile management commands')
    profile_subparsers = profile_parser.add_subparsers(dest='profile_command')
    
    setup_parser = profile_subparsers.add_parser('setup', help='Setup monitoring profile')
    setup_parser.add_argument('--log-path', required=True, help='Path to log file to monitor')
    setup_parser.add_argument('--interval', type=int, default=300, help='Monitoring interval in seconds')
    setup_parser.add_argument('--max-results', type=int, default=5, help='Maximum MITRE techniques to return')
    setup_parser.add_argument('--no-enhance', action='store_true', help='Disable AI enhancement')
    setup_parser.add_argument('--no-ai-agent', action='store_true', help='Disable AI agent')
    
    # Dynamic monitoring setup
    setup_dynamic_parser = profile_subparsers.add_parser('setup-dynamic', help='Setup dynamic log monitoring')
    setup_dynamic_parser.add_argument('--sources', nargs='*', help='Specific log sources to monitor (default: all available)')
    setup_dynamic_parser.add_argument('--interval', type=int, default=300, help='Monitoring interval in seconds')
    setup_dynamic_parser.add_argument('--no-enhance', action='store_true', help='Disable AI enhancement')
    setup_dynamic_parser.add_argument('--no-ai-agent', action='store_true', help='Disable AI agent')
    setup_dynamic_parser.add_argument('--list-sources', action='store_true', help='List available log sources')
    
    status_parser = profile_subparsers.add_parser('status', help='Show profile status')
    
    update_parser = profile_subparsers.add_parser('update', help='Update profile settings')
    update_parser.add_argument('--interval', type=int, help='Update monitoring interval')
    update_parser.add_argument('--max-results', type=int, help='Update max results')
    update_parser.add_argument('--enable-ai', action='store_true', help='Enable AI enhancement')
    update_parser.add_argument('--disable-ai', action='store_true', help='Disable AI enhancement')
    update_parser.add_argument('--enable-agent', action='store_true', help='Enable AI agent')
    update_parser.add_argument('--disable-agent', action='store_true', help='Disable AI agent')
    
    # Send commands
    send_parser = subparsers.add_parser('send', help='Send logs for analysis')
    send_parser.add_argument('--file', required=True, help='Log file to analyze')
    send_parser.add_argument('--no-enhance', action='store_true', help='Disable AI enhancement')
    
    # Monitor commands
    monitor_parser = subparsers.add_parser('monitor', help='Start log monitoring')
    monitor_parser.add_argument('--start', action='store_true', help='Start file-based monitoring')
    monitor_parser.add_argument('--dynamic', action='store_true', help='Start dynamic system monitoring')
    monitor_parser.add_argument('--schedule', action='store_true', help='Start scheduled analysis')
    monitor_parser.add_argument('--sources', nargs='*', help='Specific sources for dynamic monitoring')
    monitor_parser.add_argument('--interval', type=int, help='Override configured monitoring interval')
    
    # Analysis command
    analyze_parser = subparsers.add_parser('analyze', help='Analyze specific log file')
    analyze_parser.add_argument('--file', required=True, help='Log file to analyze')
    analyze_parser.add_argument('--enhanced', action='store_true', help='Enable enhanced AI analysis')
    analyze_parser.add_argument('--output', help='Output file for results')
    analyze_parser.add_argument('--ai-agent', action='store_true', default=True, help='Use AI agent for analysis')
    
    # AI Agent commands
    agent_parser = subparsers.add_parser('agent', help='AI Agent management commands')
    agent_subparsers = agent_parser.add_subparsers(dest='agent_command')
    
    status_parser = agent_subparsers.add_parser('status', help='Show AI agent status')
    
    config_parser = agent_subparsers.add_parser('configure', help='Configure AI agent settings')
    config_parser.add_argument('--learning-threshold', type=int, help='Pattern learning threshold')
    config_parser.add_argument('--high-threat-interval', type=int, help='High threat monitoring interval')
    config_parser.add_argument('--enable', action='store_true', help='Enable AI agent')
    config_parser.add_argument('--disable', action='store_true', help='Disable AI agent')
    
    reset_parser = agent_subparsers.add_parser('reset', help='Reset AI agent learning data')
    reset_parser.add_argument('--confirm', action='store_true', help='Confirm reset operation')
    
    # Data retrieval commands
    data_parser = subparsers.add_parser('data', help='MongoDB data retrieval commands')
    data_subparsers = data_parser.add_subparsers(dest='data_command')
    
    # Analysis data retrieval
    analysis_data_parser = data_subparsers.add_parser('analysis', help='Retrieve analysis data')
    analysis_data_parser.add_argument('--limit', type=int, default=10, help='Maximum records to retrieve')
    analysis_data_parser.add_argument('--user', help='Filter by username')
    analysis_data_parser.add_argument('--export', help='Export to file (specify filename)')
    analysis_data_parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Export format')
    
    # Monitoring sessions retrieval
    sessions_data_parser = data_subparsers.add_parser('sessions', help='Retrieve monitoring sessions')
    sessions_data_parser.add_argument('--limit', type=int, default=10, help='Maximum records to retrieve')
    sessions_data_parser.add_argument('--export', help='Export to file (specify filename)')
    sessions_data_parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Export format')
    
    # Collection statistics
    stats_parser = data_subparsers.add_parser('stats', help='Show collection statistics')
    
    # List all collections
    list_parser = data_subparsers.add_parser('list', help='List all available collections')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        return
    
    cli = ForensIQCLI()
    
    # Attempt auto-login if not a login command
    if not (args.command == 'auth' and args.auth_command == 'login'):
        if hasattr(cli, '_stored_encrypted_credentials'):
            # Only try auto-login for commands that need authentication
            needs_auth_commands = ['monitor', 'analyze', 'profile', 'agent', 'data']
            if args.command in needs_auth_commands:
                password = getpass.getpass(f"Password to decrypt stored credentials for {cli._stored_username}: ")
                cli.encryption_key = cli._generate_encryption_key(password)
                if cli._load_stored_token():
                    print(f"✓ Automatically logged in as {cli._stored_username}")
    
    # Handle commands
    if args.command == 'auth':
        if args.auth_command == 'login':
            password = args.password or getpass.getpass("Password: ")
            success = asyncio.run(cli.authenticate(args.username, password, args.api_url))
            if success:
                print("✓ Authentication successful!")
            else:
                print("✗ Authentication failed!")
                sys.exit(1)
        
        elif args.auth_command == 'register':
            password = args.password or getpass.getpass("Password: ")
            confirm_password = getpass.getpass("Confirm password: ")
            
            if password != confirm_password:
                print("✗ Passwords do not match!")
                sys.exit(1)
            
            success = asyncio.run(cli.register_user(args.username, args.email, password))
            if success:
                print("✓ Registration successful!")
                print("You can now login with your credentials.")
            else:
                print("✗ Registration failed!")
                sys.exit(1)
        
        elif args.auth_command == 'profile':
            profile = asyncio.run(cli.get_user_profile())
            if profile:
                print("\n📋 User Profile:")
                print(f"  Username: {profile.get('username')}")
                print(f"  Email: {profile.get('email')}")
                print("✓ Profile retrieved successfully!")
            else:
                print("✗ Failed to retrieve profile. Please check authentication.")
                sys.exit(1)
    
    elif args.command == 'profile':
        if args.profile_command == 'setup':
            success = asyncio.run(cli.setup_monitoring_profile(
                args.log_path, 
                args.interval, 
                args.max_results, 
                not args.no_enhance,
                not args.no_ai_agent
            ))
            if success:
                print(f"✓ Monitoring profile configured successfully!")
                print(f"  Log file: {args.log_path}")
                print(f"  Interval: {args.interval} seconds")
                print(f"  AI Enhancement: {'Enabled' if not args.no_enhance else 'Disabled'}")
                print(f"  AI Agent: {'Enabled' if not args.no_ai_agent else 'Disabled'}")
            else:
                print("✗ Failed to setup monitoring profile!")
                sys.exit(1)
        
        elif args.profile_command == 'setup-dynamic':
            if args.list_sources:
                sources = cli.get_available_log_sources()
                print("\n📋 Available Log Sources:")
                for source in sources:
                    print(f"  • {source['id']}: {source['description']} ({source['type']})")
                return
            
            success = asyncio.run(cli.setup_dynamic_monitoring(
                args.sources,
                args.interval,
                not args.no_enhance,
                not args.no_ai_agent
            ))
            if success:
                print(f"✓ Dynamic monitoring profile configured successfully!")
                if args.sources:
                    print(f"  Sources: {', '.join(args.sources)}")
                else:
                    print(f"  Sources: All available")
                print(f"  Interval: {args.interval} seconds")
                print(f"  AI Enhancement: {'Enabled' if not args.no_enhance else 'Disabled'}")
                print(f"  AI Agent: {'Enabled' if not args.no_ai_agent else 'Disabled'}")
            else:
                print("✗ Failed to setup dynamic monitoring profile!")
                sys.exit(1)
        
        elif args.profile_command == 'status':
            status = asyncio.run(cli.get_profile_status())
            print("\n📊 Profile Status:")
            print(f"  Status: {status.get('status')}")
            
            if status.get('status') == 'active':
                print(f"  User: {status.get('user')} ({status.get('email')})")
                print(f"  Log Path: {status.get('log_path')}")
                print(f"  Interval: {status.get('interval')} seconds")
                print(f"  Max Results: {status.get('max_results')}")
                print(f"  AI Enhancement: {'Enabled' if status.get('auto_enhance') else 'Disabled'}")
                print(f"  AI Agent: {'Enabled' if status.get('ai_agent_enabled') else 'Disabled'}")
                
                if status.get('log_file_size'):
                    print(f"  Log File Size: {status.get('log_file_size'):,} bytes")
                    print(f"  Last Modified: {status.get('log_file_modified')}")
                
                if status.get('ai_agent_status'):
                    agent_status = status['ai_agent_status']
                    print(f"  AI Agent Patterns: {agent_status.get('learned_patterns')}")
                    print(f"  Total Analyses: {agent_status.get('total_analyses')}")
            else:
                print(f"  Message: {status.get('message', 'Unknown error')}")
        
        elif args.profile_command == 'update':
            updates = {}
            if args.interval:
                updates['interval'] = args.interval
            if args.max_results:
                updates['max_results'] = args.max_results
            if args.enable_ai:
                updates['auto_enhance'] = True
            elif args.disable_ai:
                updates['auto_enhance'] = False
            if args.enable_agent:
                updates['enable_ai_agent'] = True
            elif args.disable_agent:
                updates['enable_ai_agent'] = False
            
            if updates:
                success = asyncio.run(cli.update_profile_settings(**updates))
                if success:
                    print("✓ Profile settings updated successfully!")
                    for key, value in updates.items():
                        print(f"  {key}: {value}")
                else:
                    print("✗ Failed to update profile settings!")
                    sys.exit(1)
            else:
                print("No settings to update. Use --help for available options.")
    
    elif args.command == 'send':
        # Check authentication
        if not cli.session_token:
            password = getpass.getpass("Password to decrypt stored credentials: ")
            credentials = cli._load_credentials(password)
            if not credentials:
                print("✗ No valid credentials found. Please login first.")
                sys.exit(1)
        
        result = asyncio.run(cli.send_log_file(args.file, not args.no_enhance))
        if result:
            print("✓ Log analysis completed!")
            print(f"Summary: {result.get('summary', 'N/A')}")
            print(f"Techniques: {len(result.get('matched_techniques', []))}")
        else:
            print("✗ Analysis failed!")
    
    elif args.command == 'monitor':
        if args.dynamic:
            # Check authentication
            if not cli.session_token:
                password = getpass.getpass("Password to decrypt stored credentials: ")
                credentials = cli._load_credentials(password)
                if not credentials:
                    print("✗ No valid credentials found. Please login first.")
                    sys.exit(1)
            
            print("🚀 Starting dynamic system log monitoring...")
            print("📊 Logs will be extracted from system sources every 5 minutes")
            print("🔄 Data will be automatically sent to ForensIQ and stored in MongoDB")
            print("🤖 AI Agent will provide enhanced analysis and adaptive scheduling")
            print("\nPress Ctrl+C to stop monitoring")
            
            # If interval is specified, update config temporarily
            if args.interval:
                original_interval = cli.config.get('dynamic_monitoring', {}).get('interval', 300)
                if 'dynamic_monitoring' not in cli.config:
                    cli.config['dynamic_monitoring'] = {}
                cli.config['dynamic_monitoring']['interval'] = args.interval
                print(f"⏱️  Using custom interval: {args.interval} seconds")
            
            try:
                asyncio.run(cli.start_dynamic_monitoring())
            except KeyboardInterrupt:
                print("\n🛑 Monitoring stopped by user")
            finally:
                # Restore original interval if it was changed
                if args.interval and 'original_interval' in locals():
                    cli.config['dynamic_monitoring']['interval'] = original_interval
        
        elif args.start:
            # Check authentication
            if not cli.session_token:
                password = getpass.getpass("Password to decrypt stored credentials: ")
                credentials = cli._load_credentials(password)
                if not credentials:
                    print("✗ No valid credentials found. Please login first.")
                    sys.exit(1)
            
            print("🚀 Starting file-based log monitoring...")
            print("📊 Logs will be automatically sent to ForensIQ and stored in MongoDB")
            print("🤖 AI Agent will provide enhanced analysis and adaptive scheduling")
            print("Press Ctrl+C to stop monitoring\n")
            
            asyncio.run(cli.start_background_monitoring())
            
        elif args.schedule:
            if not cli.session_token:
                password = getpass.getpass("Password to decrypt stored credentials: ")
                credentials = cli._load_credentials(password)
                if not credentials:
                    print("✗ No valid credentials found. Please login first.")
                    sys.exit(1)
            
            print("⏰ Starting scheduled analysis with advanced scheduling...")
            print("Press Ctrl+C to stop")
            cli.schedule_analysis()
    
    elif args.command == 'analyze':
        # Check authentication
        if not cli.session_token:
            password = getpass.getpass("Password to decrypt stored credentials: ")
            credentials = cli._load_credentials(password)
            if not credentials:
                print("✗ No valid credentials found. Please login first.")
                sys.exit(1)
        
        result = asyncio.run(cli.send_log_file(args.file, args.enhanced, args.ai_agent))
        if result:
            print("✓ Analysis completed!")
            
            # Enhanced output with AI agent insights
            if args.ai_agent and 'ai_agent_analysis' in result:
                ai_analysis = result['ai_agent_analysis']
                threat_context = ai_analysis.get('threat_context', {})
                
                print(f"\n=== AI Agent Enhanced Analysis ===")
                print(f"Threat Level: {threat_context.get('severity_level', 'Unknown')}")
                print(f"Confidence: {threat_context.get('confidence_score', 0):.2f}")
                print(f"Patterns: {len(ai_analysis.get('detected_patterns', []))}")
                print(f"Recommendations: {len(ai_analysis.get('recommendations', []))}")
                
                # Show recommendations
                recommendations = ai_analysis.get('recommendations', [])
                if recommendations:
                    print(f"\nTop Recommendations:")
                    for i, rec in enumerate(recommendations[:5], 1):
                        print(f"{i}. {rec.get('action')} (Priority: {rec.get('priority')})")
                        print(f"   {rec.get('description', '')}")
            
            if args.output:
                with open(args.output, 'w') as f:
                    json.dump(result, f, indent=2, default=str)
                print(f"Results saved to: {args.output}")
            else:
                print(json.dumps(result, indent=2, default=str))
        else:
            print("✗ Analysis failed!")
    
    elif args.command == 'agent':
        if args.agent_command == 'status':
            if cli.ai_agent:
                status = cli.ai_agent.get_agent_status()
                print("=== AI Agent Status ===")
                print(f"Status: {status['status']}")
                print(f"Learned Patterns: {status['learned_patterns']}")
                print(f"Total Analyses: {status['total_analyses']}")
                print(f"Recent Analyses (24h): {status['recent_analyses_24h']}")
                print(f"Threat History: {status['threat_history_count']}")
                if status['last_analysis']:
                    print(f"Last Analysis: {status['last_analysis']}")
                print("=====================")
            else:
                print("AI Agent is not initialized")
        
        elif args.agent_command == 'configure':
            if args.enable:
                cli.config['ai_agent_enabled'] = True
                cli.ai_agent = AIAgent(cli)
                print("✓ AI Agent enabled")
            elif args.disable:
                cli.config['ai_agent_enabled'] = False
                cli.ai_agent = None
                print("✓ AI Agent disabled")
            
            if cli.ai_agent:
                if args.learning_threshold:
                    cli.ai_agent.config['learning_threshold'] = args.learning_threshold
                if args.high_threat_interval:
                    cli.ai_agent.config['high_threat_interval'] = args.high_threat_interval
                cli.ai_agent._save_agent_state()
                print("✓ AI Agent configuration updated")
            
            cli._save_config()
        
        elif args.agent_command == 'reset':
            if args.confirm and cli.ai_agent:
                # Reset AI agent learning data
                cli.ai_agent.learned_patterns.clear()
                cli.ai_agent.analysis_history.clear()
                cli.ai_agent.threat_history.clear()
                cli.ai_agent._save_agent_state()
                print("✓ AI Agent learning data reset")
            else:
                print("Use --confirm flag to reset AI agent data")
    
    elif args.command == 'data':
        if not args.data_command:
            print("Please specify a data command. Use 'python cli_tool.py data --help' for options.")
            return
        
        if args.data_command == 'analysis':
            analysis_data = asyncio.run(cli.retrieve_analysis_data(args.limit, args.user))
            
            if args.export:
                success = asyncio.run(cli.export_collection_data('analysis', args.export, args.limit, args.format))
                if success:
                    print(f"✓ Analysis data exported to {args.export}")
                else:
                    print("✗ Failed to export analysis data")
            else:
                cli.display_analysis_data(analysis_data)
        
        elif args.data_command == 'sessions':
            sessions_data = asyncio.run(cli.retrieve_monitoring_sessions(args.limit))
            
            if args.export:
                success = asyncio.run(cli.export_collection_data('monitoring', args.export, args.limit, args.format))
                if success:
                    print(f"✓ Monitoring sessions exported to {args.export}")
                else:
                    print("✗ Failed to export monitoring sessions")
            else:
                cli.display_monitoring_sessions(sessions_data)
        
        elif args.data_command == 'stats':
            stats = asyncio.run(cli.get_collection_stats())
            cli.display_collection_stats(stats)
        
        elif args.data_command == 'list':
            print("\n📋 Available MongoDB Collections:")
            print("=" * 40)
            print("1. 🔍 analysis - Log analysis results")
            print("   - Contains MITRE ATT&CK technique matches")
            print("   - AI-enhanced threat analysis")
            print("   - User analysis history")
            print("\n2. 📊 sessions - Monitoring sessions")
            print("   - Active monitoring configurations")
            print("   - Session status and statistics")
            print("   - Log source configurations")
            print("\n3. 👥 users - User accounts")
            print("   - User authentication data")
            print("   - Profile information")
            print("\nUse 'python cli_tool.py data <collection> --help' for retrieval options.")

if __name__ == "__main__":
    main()
