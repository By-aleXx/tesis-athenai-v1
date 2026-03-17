"""
Encryption Service for AthenAI
Provides encryption/decryption for sensitive data
"""

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2
from cryptography.hazmat.backends import default_backend
import base64
import os
from typing import List, Dict, Any

class EncryptionService:
    """
    Handles encryption and decryption of sensitive data
    
    Features:
    - Symmetric encryption using Fernet (AES-128)
    - Key derivation from master password
    - Field-level encryption for dictionaries
    - Environment-based key management
    """
    
    def __init__(self, master_key: str = None):
        """
        Initialize encryption service with master key
        
        Args:
            master_key: Base64-encoded Fernet key. If None, generates or loads from env
        """
        if master_key is None:
            # Try to get from environment
            master_key = os.getenv('ENCRYPTION_KEY')
            
            if master_key is None:
                # Generate new key
                master_key = Fernet.generate_key().decode()
                print(f"⚠️  Generated new encryption key. Set ENCRYPTION_KEY env var to persist:")
                print(f"   export ENCRYPTION_KEY='{master_key}'")
        
        # Ensure key is bytes
        if isinstance(master_key, str):
            master_key = master_key.encode()
        
        try:
            self.cipher = Fernet(master_key)
            print("✅ Encryption service initialized")
        except Exception as e:
            print(f"❌ Failed to initialize encryption: {e}")
            # Fallback to a default key (NOT SECURE - for development only)
            self.cipher = Fernet(Fernet.generate_key())
            print("⚠️  Using temporary encryption key (data will not persist across restarts)")
    
    def encrypt(self, data: str) -> str:
        """
        Encrypt sensitive data
        
        Args:
            data: Plain text string to encrypt
            
        Returns:
            Base64-encoded encrypted string
        """
        if not data:
            return data
        
        try:
            encrypted = self.cipher.encrypt(data.encode())
            return base64.b64encode(encrypted).decode()
        except Exception as e:
            print(f"❌ Encryption error: {e}")
            return data  # Return original if encryption fails
    
    def decrypt(self, encrypted_data: str) -> str:
        """
        Decrypt sensitive data
        
        Args:
            encrypted_data: Base64-encoded encrypted string
            
        Returns:
            Decrypted plain text string
        """
        if not encrypted_data:
            return encrypted_data
        
        try:
            decoded = base64.b64decode(encrypted_data.encode())
            decrypted = self.cipher.decrypt(decoded)
            return decrypted.decode()
        except Exception as e:
            print(f"❌ Decryption error: {e}")
            return encrypted_data  # Return original if decryption fails
    
    def encrypt_dict(self, data: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
        """
        Encrypt specific fields in a dictionary
        
        Args:
            data: Dictionary containing data
            fields: List of field names to encrypt
            
        Returns:
            Dictionary with specified fields encrypted
        """
        encrypted_data = data.copy()
        
        for field in fields:
            if field in encrypted_data and encrypted_data[field] is not None:
                encrypted_data[field] = self.encrypt(str(encrypted_data[field]))
        
        return encrypted_data
    
    def decrypt_dict(self, data: Dict[str, Any], fields: List[str]) -> Dict[str, Any]:
        """
        Decrypt specific fields in a dictionary
        
        Args:
            data: Dictionary containing encrypted data
            fields: List of field names to decrypt
            
        Returns:
            Dictionary with specified fields decrypted
        """
        decrypted_data = data.copy()
        
        for field in fields:
            if field in decrypted_data and decrypted_data[field] is not None:
                decrypted_data[field] = self.decrypt(decrypted_data[field])
        
        return decrypted_data
    
    def encrypt_list(self, data_list: List[Dict[str, Any]], fields: List[str]) -> List[Dict[str, Any]]:
        """
        Encrypt specific fields in a list of dictionaries
        
        Args:
            data_list: List of dictionaries
            fields: List of field names to encrypt
            
        Returns:
            List of dictionaries with specified fields encrypted
        """
        return [self.encrypt_dict(item, fields) for item in data_list]
    
    def decrypt_list(self, data_list: List[Dict[str, Any]], fields: List[str]) -> List[Dict[str, Any]]:
        """
        Decrypt specific fields in a list of dictionaries
        
        Args:
            data_list: List of dictionaries with encrypted fields
            fields: List of field names to decrypt
            
        Returns:
            List of dictionaries with specified fields decrypted
        """
        return [self.decrypt_dict(item, fields) for item in data_list]
    
    @staticmethod
    def generate_key() -> str:
        """
        Generate a new Fernet key
        
        Returns:
            Base64-encoded Fernet key
        """
        return Fernet.generate_key().decode()
    
    @staticmethod
    def derive_key_from_password(password: str, salt: bytes = None) -> str:
        """
        Derive a Fernet key from a password using PBKDF2
        
        Args:
            password: Master password
            salt: Salt for key derivation (generates new if None)
            
        Returns:
            Base64-encoded Fernet key
        """
        if salt is None:
            salt = os.urandom(16)
        
        kdf = PBKDF2(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key.decode()

# Global instance
encryption_service = EncryptionService()

# Fields that should be encrypted in different contexts
SENSITIVE_FIELDS = {
    'block_events': ['source_ip', 'user_agent', 'payload', 'headers'],
    'traffic_logs': ['source_ip', 'user_agent', 'query_params', 'body'],
    'alerts': ['source_ip', 'details'],
    'users': ['email', 'phone'],
}

def get_sensitive_fields(context: str) -> List[str]:
    """Get list of sensitive fields for a given context"""
    return SENSITIVE_FIELDS.get(context, [])

if __name__ == "__main__":
    # Test encryption service
    print("Testing Encryption Service...")
    
    # Test basic encryption/decryption
    original = "192.168.1.100"
    encrypted = encryption_service.encrypt(original)
    decrypted = encryption_service.decrypt(encrypted)
    
    print(f"\nOriginal: {original}")
    print(f"Encrypted: {encrypted}")
    print(f"Decrypted: {decrypted}")
    print(f"Match: {original == decrypted}")
    
    # Test dictionary encryption
    data = {
        'source_ip': '192.168.1.100',
        'path': '/api/test',
        'payload': "id=1' OR '1'='1",
        'timestamp': '2026-02-14T17:00:00'
    }
    
    print("\nOriginal data:")
    print(data)
    
    encrypted_data = encryption_service.encrypt_dict(data, ['source_ip', 'payload'])
    print("\nEncrypted data:")
    print(encrypted_data)
    
    decrypted_data = encryption_service.decrypt_dict(encrypted_data, ['source_ip', 'payload'])
    print("\nDecrypted data:")
    print(decrypted_data)
    
    print(f"\nMatch: {data == decrypted_data}")
    
    # Test key generation
    new_key = EncryptionService.generate_key()
    print(f"\nGenerated key: {new_key}")
    
    # Test password-based key derivation
    password = "my_secure_password"
    derived_key = EncryptionService.derive_key_from_password(password)
    print(f"Derived key from password: {derived_key}")
