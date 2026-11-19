"""
Encryption service for sensitive analysis data.
Provides AES-256 encryption with key derivation and secure key management.
"""

import os
import json
import hashlib
import base64
from typing import Dict, Any, Optional, Tuple
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from datetime import datetime
import secrets

from core.config import settings
from core import logger

class EncryptionService:
    """Service for encrypting and decrypting sensitive analysis data."""
    
    def __init__(self):
        self.master_key = settings.ENCRYPTION_MASTER_KEY.encode()
        self.salt_length = 32
        self.key_iteration_count = 100000
    
    def _derive_key(self, password: bytes, salt: bytes) -> bytes:
        """Derive encryption key from password and salt using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=self.key_iteration_count,
        )
        return base64.urlsafe_b64encode(kdf.derive(password))
    
    def _generate_user_key(self, user_id: str) -> Tuple[bytes, str]:
        """Generate a unique encryption key for a user."""
        # Create a deterministic but secure salt for the user
        user_salt = hashlib.sha256(f"{user_id}_{settings.SECRET_KEY}".encode()).digest()
        
        # Use deterministic salt generation instead of random
        # This ensures the same user always gets the same key
        deterministic_salt = hashlib.sha256(f"{user_id}_{settings.SECRET_KEY}_salt".encode()).digest()
        combined_salt = user_salt + deterministic_salt[:self.salt_length]
        
        # Derive key from master key and combined salt
        key = self._derive_key(self.master_key, combined_salt)
        
        # Create key ID for reference
        key_id = hashlib.sha256(key).hexdigest()[:16]
        
        return key, key_id
    
    def encrypt_data(self, data: Any, user_id: str) -> Tuple[str, str]:
        """
        Encrypt data for a specific user.
        
        Args:
            data: Data to encrypt (will be JSON serialized)
            user_id: User identifier
            
        Returns:
            Tuple of (encrypted_data_base64, key_id)
        """
        try:
            # Serialize data to JSON
            json_data = json.dumps(data, default=str, ensure_ascii=False)
            
            # Generate user-specific key
            key, key_id = self._generate_user_key(user_id)
            
            # Create Fernet cipher
            cipher = Fernet(key)
            
            # Encrypt the data
            encrypted_data = cipher.encrypt(json_data.encode('utf-8'))
            
            # Encode to base64 for storage
            encrypted_b64 = base64.b64encode(encrypted_data).decode('ascii')
            
            logger.info(f"Successfully encrypted data for user {user_id} with key ID {key_id}")
            return encrypted_b64, key_id
            
        except Exception as e:
            logger.error(f"Failed to encrypt data for user {user_id}: {str(e)}")
            raise
    
    def decrypt_data(self, encrypted_data_b64: str, user_id: str, key_id: str) -> Any:
        """
        Decrypt data for a specific user.
        
        Args:
            encrypted_data_b64: Base64 encoded encrypted data
            user_id: User identifier
            key_id: Key ID used for encryption
            
        Returns:
            Decrypted and deserialized data
        """
        try:
            # Generate the user key
            key, regenerated_key_id = self._generate_user_key(user_id)
            
            # Decode from base64
            encrypted_data = base64.b64decode(encrypted_data_b64.encode('ascii'))
            
            # Create Fernet cipher
            cipher = Fernet(key)
            
            # Decrypt the data
            decrypted_data = cipher.decrypt(encrypted_data)
            
            # Deserialize JSON
            json_str = decrypted_data.decode('utf-8')
            return json.loads(json_str)
            
        except Exception as e:
            logger.error(f"Failed to decrypt data for user {user_id}: {str(e)}")
            return None
    
    def hash_data(self, data: str) -> str:
        """Create a hash of data for integrity verification."""
        return hashlib.sha256(data.encode('utf-8')).hexdigest()
    
    def encrypt_logs(self, logs: str, user_id: str) -> Tuple[str, str, str]:
        """
        Encrypt logs and create hash for deduplication.
        
        Returns:
            Tuple of (encrypted_logs, logs_hash, key_id)
        """
        logs_hash = self.hash_data(logs)
        encrypted_logs, key_id = self.encrypt_data(logs, user_id)
        return encrypted_logs, logs_hash, key_id
    
    def encrypt_analysis_results(self,
                               summary: str,
                               techniques: list,
                               enhanced_analysis: Optional[str],
                               hashed_password: str) -> Tuple[Dict[str, str], str]:
        """
        Encrypt all analysis results using user's hashed password as key.
        
        Args:
            summary: Analysis summary text
            techniques: List of techniques
            enhanced_analysis: Optional enhanced analysis
            hashed_password: User's hashed password to use as encryption key
        
        Returns:
            Tuple of (encrypted_data_dict, key_id)
        """
        # Use hashed password directly for encryption key derivation
        key_material = hashlib.sha256(hashed_password.encode()).digest()
        key = base64.urlsafe_b64encode(key_material)
        key_id = f"pwd_{hashlib.md5(hashed_password.encode()).hexdigest()[:8]}"
        logger.info(f"Using hashed password for encryption: {key_id}")
        
        cipher = Fernet(key)
        
        encrypted_data = {}
        
        # Encrypt summary
        encrypted_data['summary'] = cipher.encrypt(summary.encode('utf-8')).decode('ascii')
        
        # Encrypt techniques (as JSON)
        techniques_json = json.dumps(techniques)
        encrypted_data['techniques'] = cipher.encrypt(techniques_json.encode('utf-8')).decode('ascii')
        
        # Encrypt enhanced analysis if provided
        if enhanced_analysis:
            encrypted_data['enhanced_analysis'] = cipher.encrypt(enhanced_analysis.encode('utf-8')).decode('ascii')
        
        return encrypted_data, key_id

    def decrypt_analysis_results(self,
                                 encrypted_data: Dict[str, str],
                                 hashed_password: str) -> Dict[str, Any]:
        """Decrypt all analysis results using user's hashed password as key.
        
        Args:
            encrypted_data: Dictionary of encrypted data
            hashed_password: User's hashed password to use as decryption key
        """
        try:
            # Use hashed password directly for decryption key derivation
            key_material = hashlib.sha256(hashed_password.encode()).digest()
            key = base64.urlsafe_b64encode(key_material)
            logger.info(f"Using hashed password for decryption")
                
            cipher = Fernet(key)
            
            decrypted_data = {}
            
            # Decrypt summary
            if encrypted_data.get('summary'):
                try:
                    decrypted_data['summary'] = cipher.decrypt(encrypted_data['summary'].encode('ascii')).decode('utf-8')
                except Exception:
                    decrypted_data['summary'] = ""
            else:
                decrypted_data['summary'] = ""
            
            # Decrypt techniques
            if encrypted_data.get('techniques'):
                try:
                    decrypted_techniques_json = cipher.decrypt(encrypted_data['techniques'].encode('ascii')).decode('utf-8')
                    decrypted_data['techniques'] = json.loads(decrypted_techniques_json)
                except Exception:
                    decrypted_data['techniques'] = []
            else:
                decrypted_data['techniques'] = []
            
            # Decrypt enhanced analysis if present
            if encrypted_data.get('enhanced_analysis'):
                try:
                    decrypted_data['enhanced_analysis'] = cipher.decrypt(encrypted_data['enhanced_analysis'].encode('ascii')).decode('utf-8')
                except Exception:
                    decrypted_data['enhanced_analysis'] = None
            else:
                decrypted_data['enhanced_analysis'] = None
                
            return decrypted_data
        
        except Exception as e:
            logger.error(f"Failed to decrypt analysis results: {str(e)}")
            return {
                'summary': "",
                'techniques': [],
                'enhanced_analysis': None
            }

# Global service instance
encryption_service = EncryptionService()
