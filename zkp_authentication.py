import hashlib
import hmac
import secrets
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional, Any
import numpy as np
import base64
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
import jwt
import time
import threading
from dataclasses import dataclass
from enum import Enum

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class BiometricType(Enum):
    KEYSTROKE = "keystroke"
    VOICE = "voice"
    BEHAVIOR = "behavior"
    FACE = "face"

@dataclass
class BiometricTemplate:
    """Biometric template for ZKP authentication"""
    user_id: str
    biometric_type: BiometricType
    template_hash: str
    salt: str
    created_at: datetime
    last_updated: datetime

class ZeroKnowledgeProof:
    """
    Zero-Knowledge Proof implementation for biometric authentication
    """
    
    def __init__(self, private_key: str = None):
        self.private_key = private_key or secrets.token_hex(32)
        self.public_key = self._derive_public_key()
        self.challenge_history = {}
        self.proof_history = {}
        
        logger.info("Zero-Knowledge Proof system initialized")
    
    def _derive_public_key(self) -> str:
        """Derive public key from private key"""
        return hashlib.sha256(self.private_key.encode()).hexdigest()
    
    def generate_challenge(self, user_id: str) -> Dict:
        """
        Generate a challenge for ZKP authentication
        """
        challenge = {
            'challenge_id': secrets.token_hex(16),
            'timestamp': datetime.now().isoformat(),
            'nonce': secrets.token_hex(32),
            'user_id': user_id,
            'expires_at': (datetime.now() + timedelta(minutes=5)).isoformat()
        }
        
        # Store challenge
        self.challenge_history[challenge['challenge_id']] = challenge
        
        return challenge
    
    def create_proof(self, challenge: Dict, biometric_data: Dict, 
                     biometric_template: BiometricTemplate) -> Dict:
        """
        Create a zero-knowledge proof for biometric authentication
        """
        if challenge['challenge_id'] not in self.challenge_history:
            raise ValueError("Invalid or expired challenge")
        
        # Verify biometric match without revealing the actual biometric data
        match_score = self._verify_biometric_match(biometric_data, biometric_template)
        
        if match_score < 0.85:  # 85% threshold
            raise ValueError("Biometric verification failed")
        
        # Create ZKP proof
        proof = {
            'proof_id': secrets.token_hex(16),
            'challenge_id': challenge['challenge_id'],
            'timestamp': datetime.now().isoformat(),
            'user_id': challenge['user_id'],
            'biometric_type': biometric_template.biometric_type.value,
            'match_verified': True,
            'proof_signature': self._sign_proof(challenge, biometric_template),
            'public_commitment': self._create_public_commitment(biometric_template)
        }
        
        # Store proof
        self.proof_history[proof['proof_id']] = proof
        
        return proof
    
    def verify_proof(self, proof: Dict, challenge: Dict) -> bool:
        """
        Verify a zero-knowledge proof
        """
        try:
            # Check if proof exists
            if proof['proof_id'] not in self.proof_history:
                return False
            
            # Verify challenge
            if challenge['challenge_id'] != proof['challenge_id']:
                return False
            
            # Verify signature
            if not self._verify_proof_signature(proof, challenge):
                return False
            
            # Verify timestamp
            proof_time = datetime.fromisoformat(proof['timestamp'])
            challenge_time = datetime.fromisoformat(challenge['timestamp'])
            if (proof_time - challenge_time).total_seconds() > 300:  # 5 minutes
                return False
            
            return True
        
        except Exception as e:
            logger.error(f"Proof verification error: {str(e)}")
            return False
    
    def _verify_biometric_match(self, biometric_data: Dict, 
                               template: BiometricTemplate) -> float:
        """
        Verify biometric match without revealing actual data
        """
        # Extract biometric features based on type
        if template.biometric_type == BiometricType.KEYSTROKE:
            return self._verify_keystroke_pattern(biometric_data, template)
        elif template.biometric_type == BiometricType.VOICE:
            return self._verify_voice_pattern(biometric_data, template)
        elif template.biometric_type == BiometricType.BEHAVIOR:
            return self._verify_behavior_pattern(biometric_data, template)
        else:
            return 0.0
    
    def _verify_keystroke_pattern(self, biometric_data: Dict, 
                                 template: BiometricTemplate) -> float:
        """
        Verify keystroke pattern using timing analysis
        """
        try:
            # Extract keystroke timing data
            keystroke_times = biometric_data.get('keystroke_times', [])
            if not keystroke_times:
                return 0.0
            
            # Calculate timing patterns
            timing_pattern = self._extract_timing_pattern(keystroke_times)
            
            # Compare with template (simplified)
            template_pattern = self._decode_template(template.template_hash)
            
            # Calculate similarity score
            similarity = self._calculate_pattern_similarity(timing_pattern, template_pattern)
            
            return similarity
        
        except Exception as e:
            logger.error(f"Keystroke verification error: {str(e)}")
            return 0.0
    
    def _verify_voice_pattern(self, biometric_data: Dict, 
                             template: BiometricTemplate) -> float:
        """
        Verify voice pattern using audio features
        """
        try:
            # Extract voice features
            voice_features = biometric_data.get('voice_features', {})
            if not voice_features:
                return 0.0
            
            # Compare with template
            template_features = self._decode_template(template.template_hash)
            
            # Calculate voice similarity
            similarity = self._calculate_voice_similarity(voice_features, template_features)
            
            return similarity
        
        except Exception as e:
            logger.error(f"Voice verification error: {str(e)}")
            return 0.0
    
    def _verify_behavior_pattern(self, biometric_data: Dict, 
                                template: BiometricTemplate) -> float:
        """
        Verify behavioral pattern using user behavior analysis
        """
        try:
            # Extract behavioral features
            behavior_features = biometric_data.get('behavior_features', {})
            if not behavior_features:
                return 0.0
            
            # Compare with template
            template_features = self._decode_template(template.template_hash)
            
            # Calculate behavior similarity
            similarity = self._calculate_behavior_similarity(behavior_features, template_features)
            
            return similarity
        
        except Exception as e:
            logger.error(f"Behavior verification error: {str(e)}")
            return 0.0
    
    def _extract_timing_pattern(self, keystroke_times: List[float]) -> List[float]:
        """Extract timing pattern from keystroke data"""
        if len(keystroke_times) < 2:
            return []
        
        # Calculate intervals between keystrokes
        intervals = []
        for i in range(1, len(keystroke_times)):
            interval = keystroke_times[i] - keystroke_times[i-1]
            intervals.append(interval)
        
        return intervals
    
    def _calculate_pattern_similarity(self, pattern1: List[float], 
                                    pattern2: List[float]) -> float:
        """Calculate similarity between two patterns"""
        if not pattern1 or not pattern2:
            return 0.0
        
        # Normalize patterns
        pattern1_norm = np.array(pattern1) / np.sum(pattern1) if np.sum(pattern1) > 0 else pattern1
        pattern2_norm = np.array(pattern2) / np.sum(pattern2) if np.sum(pattern2) > 0 else pattern2
        
        # Calculate cosine similarity
        similarity = np.dot(pattern1_norm, pattern2_norm) / (
            np.linalg.norm(pattern1_norm) * np.linalg.norm(pattern2_norm)
        )
        
        return float(similarity)
    
    def _calculate_voice_similarity(self, features1: Dict, features2: Dict) -> float:
        """Calculate voice similarity"""
        # Simplified voice similarity calculation
        common_keys = set(features1.keys()) & set(features2.keys())
        if not common_keys:
            return 0.0
        
        similarities = []
        for key in common_keys:
            val1 = features1[key]
            val2 = features2[key]
            if isinstance(val1, (int, float)) and isinstance(val2, (int, float)):
                similarity = 1.0 - abs(val1 - val2) / max(abs(val1), abs(val2), 1e-6)
                similarities.append(similarity)
        
        return np.mean(similarities) if similarities else 0.0
    
    def _calculate_behavior_similarity(self, features1: Dict, features2: Dict) -> float:
        """Calculate behavior similarity"""
        # Simplified behavior similarity calculation
        return self._calculate_voice_similarity(features1, features2)
    
    def _decode_template(self, template_hash: str) -> Any:
        """Decode template from hash (simplified)"""
        # In a real implementation, this would decode the actual template
        # For demo purposes, we'll return a simple pattern
        return [0.1, 0.2, 0.3, 0.4, 0.5]
    
    def _sign_proof(self, challenge: Dict, template: BiometricTemplate) -> str:
        """Sign the proof with private key"""
        proof_data = f"{challenge['challenge_id']}{template.user_id}{template.biometric_type.value}"
        signature = hmac.new(
            self.private_key.encode(),
            proof_data.encode(),
            hashlib.sha256
        ).hexdigest()
        
        return signature
    
    def _verify_proof_signature(self, proof: Dict, challenge: Dict) -> bool:
        """Verify proof signature"""
        expected_signature = self._sign_proof(challenge, 
                                            BiometricTemplate(
                                                user_id=proof['user_id'],
                                                biometric_type=BiometricType(proof['biometric_type']),
                                                template_hash="",
                                                salt="",
                                                created_at=datetime.now(),
                                                last_updated=datetime.now()
                                            ))
        
        return proof['proof_signature'] == expected_signature
    
    def _create_public_commitment(self, template: BiometricTemplate) -> str:
        """Create public commitment for ZKP"""
        commitment_data = f"{template.user_id}{template.biometric_type.value}{template.template_hash}"
        return hashlib.sha256(commitment_data.encode()).hexdigest()

class ZKPAuthenticationSystem:
    """
    Main ZKP Authentication System for educational institutions
    """
    
    def __init__(self):
        self.zkp = ZeroKnowledgeProof()
        self.user_templates = {}
        self.active_sessions = {}
        self.authentication_history = []
        
        logger.info("ZKP Authentication System initialized")
    
    def register_user(self, user_id: str, biometric_data: Dict, 
                     biometric_type: BiometricType) -> bool:
        """
        Register a user with biometric template
        """
        try:
            # Create biometric template
            salt = secrets.token_hex(16)
            template_data = self._create_template_data(biometric_data, biometric_type)
            template_hash = hashlib.sha256(
                (template_data + salt).encode()
            ).hexdigest()
            
            template = BiometricTemplate(
                user_id=user_id,
                biometric_type=biometric_type,
                template_hash=template_hash,
                salt=salt,
                created_at=datetime.now(),
                last_updated=datetime.now()
            )
            
            # Store template
            self.user_templates[user_id] = template
            
            logger.info(f"User {user_id} registered with {biometric_type.value} biometrics")
            return True
        
        except Exception as e:
            logger.error(f"User registration error: {str(e)}")
            return False
    
    def authenticate_user(self, user_id: str, biometric_data: Dict, 
                        biometric_type: BiometricType) -> Dict:
        """
        Authenticate user using ZKP
        """
        try:
            # Check if user exists
            if user_id not in self.user_templates:
                raise ValueError("User not registered")
            
            template = self.user_templates[user_id]
            
            # Generate challenge
            challenge = self.zkp.generate_challenge(user_id)
            
            # Create proof
            proof = self.zkp.create_proof(challenge, biometric_data, template)
            
            # Verify proof
            if not self.zkp.verify_proof(proof, challenge):
                raise ValueError("Proof verification failed")
            
            # Create session
            session_token = self._create_session(user_id, proof)
            
            # Record authentication
            auth_record = {
                'timestamp': datetime.now().isoformat(),
                'user_id': user_id,
                'biometric_type': biometric_type.value,
                'success': True,
                'session_token': session_token,
                'proof_id': proof['proof_id']
            }
            
            self.authentication_history.append(auth_record)
            
            logger.info(f"User {user_id} authenticated successfully")
            
            return {
                'success': True,
                'session_token': session_token,
                'proof_id': proof['proof_id'],
                'expires_at': (datetime.now() + timedelta(hours=24)).isoformat()
            }
        
        except Exception as e:
            logger.error(f"Authentication error: {str(e)}")
            
            # Record failed authentication
            auth_record = {
                'timestamp': datetime.now().isoformat(),
                'user_id': user_id,
                'biometric_type': biometric_type.value if 'biometric_type' in locals() else 'unknown',
                'success': False,
                'error': str(e)
            }
            
            self.authentication_history.append(auth_record)
            
            return {
                'success': False,
                'error': str(e)
            }
    
    def verify_session(self, session_token: str) -> bool:
        """
        Verify active session
        """
        if session_token not in self.active_sessions:
            return False
        
        session = self.active_sessions[session_token]
        if datetime.now() > session['expires_at']:
            del self.active_sessions[session_token]
            return False
        
        return True
    
    def verify_document_anonymously(self, document_hash: str, 
                                   user_id: str, session_token: str) -> Dict:
        """
        Verify document integrity anonymously using ZKP
        """
        try:
            # Verify session
            if not self.verify_session(session_token):
                raise ValueError("Invalid or expired session")
            
            # Create anonymous proof
            anonymous_proof = {
                'proof_id': secrets.token_hex(16),
                'document_hash': document_hash,
                'user_id_commitment': self._create_user_commitment(user_id),
                'timestamp': datetime.now().isoformat(),
                'verification_signature': self._sign_document_verification(document_hash, user_id)
            }
            
            # Verify document integrity (simplified)
            document_valid = self._verify_document_integrity(document_hash)
            
            return {
                'success': True,
                'document_valid': document_valid,
                'anonymous_proof': anonymous_proof,
                'verification_timestamp': datetime.now().isoformat()
            }
        
        except Exception as e:
            logger.error(f"Document verification error: {str(e)}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _create_template_data(self, biometric_data: Dict, 
                            biometric_type: BiometricType) -> str:
        """Create template data from biometric input"""
        if biometric_type == BiometricType.KEYSTROKE:
            return self._extract_keystroke_template(biometric_data)
        elif biometric_type == BiometricType.VOICE:
            return self._extract_voice_template(biometric_data)
        elif biometric_type == BiometricType.BEHAVIOR:
            return self._extract_behavior_template(biometric_data)
        else:
            return json.dumps(biometric_data)
    
    def _extract_keystroke_template(self, biometric_data: Dict) -> str:
        """Extract keystroke template"""
        keystroke_times = biometric_data.get('keystroke_times', [])
        timing_pattern = self.zkp._extract_timing_pattern(keystroke_times)
        return json.dumps(timing_pattern)
    
    def _extract_voice_template(self, biometric_data: Dict) -> str:
        """Extract voice template"""
        voice_features = biometric_data.get('voice_features', {})
        return json.dumps(voice_features)
    
    def _extract_behavior_template(self, biometric_data: Dict) -> str:
        """Extract behavior template"""
        behavior_features = biometric_data.get('behavior_features', {})
        return json.dumps(behavior_features)
    
    def _create_session(self, user_id: str, proof: Dict) -> str:
        """Create authentication session"""
        session_token = secrets.token_hex(32)
        
        self.active_sessions[session_token] = {
            'user_id': user_id,
            'proof_id': proof['proof_id'],
            'created_at': datetime.now(),
            'expires_at': datetime.now() + timedelta(hours=24)
        }
        
        return session_token
    
    def _create_user_commitment(self, user_id: str) -> str:
        """Create anonymous user commitment"""
        return hashlib.sha256(f"{user_id}{self.zkp.private_key}".encode()).hexdigest()
    
    def _sign_document_verification(self, document_hash: str, user_id: str) -> str:
        """Sign document verification"""
        verification_data = f"{document_hash}{user_id}{datetime.now().isoformat()}"
        return hmac.new(
            self.zkp.private_key.encode(),
            verification_data.encode(),
            hashlib.sha256
        ).hexdigest()
    
    def _verify_document_integrity(self, document_hash: str) -> bool:
        """Verify document integrity (simplified)"""
        # In a real implementation, this would check against a blockchain
        # For demo purposes, we'll assume valid
        return True
    
    def get_authentication_stats(self) -> Dict:
        """Get authentication statistics"""
        total_attempts = len(self.authentication_history)
        successful_attempts = len([a for a in self.authentication_history if a['success']])
        success_rate = (successful_attempts / total_attempts * 100) if total_attempts > 0 else 0
        
        return {
            'total_attempts': total_attempts,
            'successful_attempts': successful_attempts,
            'success_rate': success_rate,
            'active_sessions': len(self.active_sessions),
            'registered_users': len(self.user_templates)
        }
    
    def export_authentication_log(self, filepath: str):
        """Export authentication history"""
        log_data = {
            'export_timestamp': datetime.now().isoformat(),
            'authentication_history': self.authentication_history,
            'statistics': self.get_authentication_stats()
        }
        
        with open(filepath, 'w') as f:
            json.dump(log_data, f, indent=2)
        
        logger.info(f"Authentication log exported to {filepath}")


# Example usage
if __name__ == "__main__":
    # Initialize ZKP authentication system
    auth_system = ZKPAuthenticationSystem()
    
    # Example user registration
    user_id = "student_123"
    biometric_data = {
        'keystroke_times': [0.1, 0.3, 0.6, 0.8, 1.2, 1.5],
        'voice_features': {'pitch': 150, 'frequency': 2000},
        'behavior_features': {'typing_speed': 60, 'mouse_pattern': 'normal'}
    }
    
    # Register user with keystroke biometrics
    success = auth_system.register_user(user_id, biometric_data, BiometricType.KEYSTROKE)
    print(f"User registration: {'SUCCESS' if success else 'FAILED'}")
    
    # Authenticate user
    auth_result = auth_system.authenticate_user(user_id, biometric_data, BiometricType.KEYSTROKE)
    
    if auth_result['success']:
        print(f"Authentication: SUCCESS")
        print(f"Session token: {auth_result['session_token']}")
        
        # Verify document anonymously
        document_hash = "abc123def456"
        verification_result = auth_system.verify_document_anonymously(
            document_hash, user_id, auth_result['session_token']
        )
        
        if verification_result['success']:
            print(f"Document verification: {'VALID' if verification_result['document_valid'] else 'INVALID'}")
    
    else:
        print(f"Authentication: FAILED - {auth_result['error']}")
    
    # Print statistics
    stats = auth_system.get_authentication_stats()
    print(f"\nAuthentication Statistics:")
    print(f"Success Rate: {stats['success_rate']:.1f}%")
    print(f"Total Attempts: {stats['total_attempts']}")
    print(f"Active Sessions: {stats['active_sessions']}") 