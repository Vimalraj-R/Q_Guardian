import os
import hashlib
import json
import logging
from datetime import datetime
from typing import Dict, List, Optional, Any
from pathlib import Path
import magic
import mimetypes
import base64
import zipfile
import xml.etree.ElementTree as ET
from PIL import Image
import io
import struct
import shutil
import tempfile

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class FileVerificationSystem:
    """
    Comprehensive File Verification System for QGuardian
    Features:
    - File integrity checking
    - Malware detection
    - Metadata analysis
    - Content validation
    - Security scoring
    - Blockchain recording
    """
    
    def __init__(self):
        self.supported_formats = {
            '.pdf', '.docx', '.doc', '.txt', '.rtf', '.odt',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff',
            '.xlsx', '.xls', '.csv', '.ppt', '.pptx'
        }
        
        # Security policies for different file types
        self.security_policies = {
            'exam_paper': {
                'max_size_mb': 50,
                'allowed_formats': ['.pdf', '.docx'],
                'required_encryption': True,
                'sensitive_content': True,
                'verification_level': 'HIGH'
            },
            'assignment': {
                'max_size_mb': 25,
                'allowed_formats': ['.pdf', '.docx', '.txt'],
                'required_encryption': False,
                'sensitive_content': False,
                'verification_level': 'MEDIUM'
            },
            'grade_report': {
                'max_size_mb': 10,
                'allowed_formats': ['.pdf', '.xlsx'],
                'required_encryption': True,
                'sensitive_content': True,
                'verification_level': 'HIGH'
            },
            'research_paper': {
                'max_size_mb': 100,
                'allowed_formats': ['.pdf', '.docx'],
                'required_encryption': False,
                'sensitive_content': False,
                'verification_level': 'MEDIUM'
            },
            'certificate': {
                'max_size_mb': 5,
                'allowed_formats': ['.pdf', '.png', '.jpg'],
                'required_encryption': True,
                'sensitive_content': True,
                'verification_level': 'HIGH'
            }
        }
        
        # Initialize verification history
        self.verification_history = []
        
        logger.info("File Verification System initialized")
    
    def verify_file(self, file_path: str, file_type: str = "assignment", user_id: str = None) -> Dict:
        """
        Comprehensive file verification
        """
        logger.info(f"Verifying file: {file_path}")
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"File not found: {file_path}")
        
        # Initialize verification results
        verification_result = {
            'timestamp': datetime.now().isoformat(),
            'file_path': file_path,
            'file_name': os.path.basename(file_path),
            'file_type': file_type,
            'user_id': user_id,
            'file_size_bytes': os.path.getsize(file_path),
            'file_hash': None,
            'verification_status': 'PENDING',
            'security_score': 0,
            'integrity_check': False,
            'malware_check': False,
            'metadata_check': False,
            'content_check': False,
            'policy_compliance': False,
            'issues_found': [],
            'recommendations': [],
            'verification_details': {}
        }
        
        try:
            # 1. Generate file hash
            file_hash = self._generate_file_hash(file_path)
            verification_result['file_hash'] = file_hash
            
            # 2. Check file integrity
            integrity_result = self._check_file_integrity(file_path)
            verification_result['integrity_check'] = integrity_result['is_valid']
            verification_result['issues_found'].extend(integrity_result['issues'])
            
            # 3. Malware detection
            malware_result = self._detect_malware(file_path)
            verification_result['malware_check'] = malware_result['is_clean']
            verification_result['issues_found'].extend(malware_result['issues'])
            
            # 4. Metadata analysis
            metadata_result = self._analyze_metadata(file_path, file_type)
            verification_result['metadata_check'] = metadata_result['is_secure']
            verification_result['issues_found'].extend(metadata_result['issues'])
            
            # 5. Content validation
            content_result = self._validate_content(file_path, file_type)
            verification_result['content_check'] = content_result['is_valid']
            verification_result['issues_found'].extend(content_result['issues'])
            
            # 6. Policy compliance
            policy_result = self._check_policy_compliance(file_path, file_type)
            verification_result['policy_compliance'] = policy_result['is_compliant']
            verification_result['issues_found'].extend(policy_result['issues'])
            verification_result['recommendations'].extend(policy_result['recommendations'])
            
            # 7. Calculate security score
            verification_result['security_score'] = self._calculate_security_score(verification_result)
            
            # 8. Determine verification status
            verification_result['verification_status'] = self._determine_verification_status(verification_result)
            
            # 9. Record in history
            self._record_verification(verification_result)
            
            logger.info(f"File verification completed. Status: {verification_result['verification_status']}")
            
        except Exception as e:
            logger.error(f"Error verifying file: {str(e)}")
            verification_result['issues_found'].append(f"Verification error: {str(e)}")
            verification_result['verification_status'] = 'FAILED'
            verification_result['security_score'] = 0
        
        return verification_result
    
    def _generate_file_hash(self, file_path: str) -> str:
        """Generate SHA-256 hash for file"""
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()
    
    def _check_file_integrity(self, file_path: str) -> Dict:
        """Check file integrity and structure"""
        result = {
            'is_valid': True,
            'issues': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            file_extension = Path(file_path).suffix.lower()
            
            # Check file structure based on type
            if file_extension == '.pdf':
                if not content.startswith(b'%PDF'):
                    result['is_valid'] = False
                    result['issues'].append("Invalid PDF structure")
            
            elif file_extension in ['.docx', '.xlsx', '.pptx']:
                if not content.startswith(b'PK'):
                    result['is_valid'] = False
                    result['issues'].append("Invalid Office document structure")
            
            elif file_extension in ['.jpg', '.jpeg']:
                if not content.startswith(b'\xff\xd8\xff'):
                    result['is_valid'] = False
                    result['issues'].append("Invalid JPEG structure")
            
            elif file_extension == '.png':
                if not content.startswith(b'\x89PNG\r\n\x1a\n'):
                    result['is_valid'] = False
                    result['issues'].append("Invalid PNG structure")
            
            # Check for file corruption indicators
            if len(content) == 0:
                result['is_valid'] = False
                result['issues'].append("Empty file")
            
            # Check for suspicious patterns
            suspicious_patterns = [b'virus', b'malware', b'exploit', b'shell']
            for pattern in suspicious_patterns:
                if pattern in content.lower():
                    result['issues'].append(f"Suspicious content detected: {pattern.decode()}")
        
        except Exception as e:
            result['is_valid'] = False
            result['issues'].append(f"File integrity check error: {str(e)}")
        
        return result
    
    def _detect_malware(self, file_path: str) -> Dict:
        """Detect potential malware in file"""
        result = {
            'is_clean': True,
            'issues': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Check for executable content in non-executable files
            file_extension = Path(file_path).suffix.lower()
            if file_extension in ['.pdf', '.docx', '.txt']:
                # Check for embedded executables
                if b'MZ' in content:  # DOS executable header
                    result['is_clean'] = False
                    result['issues'].append("Potential embedded executable detected")
                
                # Check for suspicious macros
                if b'VBA' in content or b'Macro' in content:
                    result['issues'].append("Macros detected - review required")
                
                # Check for suspicious URLs
                if b'http://' in content or b'https://' in content:
                    result['issues'].append("URLs detected in document")
            
            # Check for known malware signatures (simplified)
            malware_signatures = [
                b'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*',
                b'TVqQAAMAAAAEAAAA//8AALgAAAAAAAAAQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAA4fug4AtAnNIbgBTM0hVGhpcyBwcm9ncmFtIGNhbm5vdCBiZSBydW4gaW4gRE9TIG1vZGUuDQ0KJAAAAAAAAABQRQAATAEDAKJd6V8AAAAAAAAAAOAAIiALATAAAA4AAAAGAAAAAAAAVicAAAAgAAAAQAAAAAAAEAAgAAAAAgAABAAAAAAAAAAGAAAAAAAAAACAAAAAAgAAAAAAAAMAYIUAABAAABAAAAAAEAAAEAAAAAAAABAAAAAAAAAAAAAAAGQnAABPAAAAAEAAAIgDAAAAAAAAAAAAAAAAAAAAAAAAAGAAAAwAAADcJAAAOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=='
            ]
            
            for signature in malware_signatures:
                if signature in content:
                    result['is_clean'] = False
                    result['issues'].append("Known malware signature detected")
        
        except Exception as e:
            result['issues'].append(f"Malware detection error: {str(e)}")
        
        return result
    
    def _analyze_metadata(self, file_path: str, file_type: str) -> Dict:
        """Analyze file metadata for security"""
        result = {
            'is_secure': True,
            'issues': [],
            'metadata_found': {}
        }
        
        try:
            file_extension = Path(file_path).suffix.lower()
            
            if file_extension == '.pdf':
                result.update(self._analyze_pdf_metadata(file_path))
            elif file_extension in ['.docx', '.xlsx', '.pptx']:
                result.update(self._analyze_office_metadata(file_path))
            elif file_extension in ['.jpg', '.jpeg', '.png']:
                result.update(self._analyze_image_metadata(file_path))
            else:
                result.update(self._analyze_generic_metadata(file_path))
        
        except Exception as e:
            result['issues'].append(f"Metadata analysis error: {str(e)}")
            result['is_secure'] = False
        
        return result
    
    def _analyze_pdf_metadata(self, file_path: str) -> Dict:
        """Analyze PDF metadata"""
        result = {'metadata_found': {}, 'issues': [], 'recommendations': []}
        
        try:
            import PyPDF2
            with open(file_path, 'rb') as file:
                pdf_reader = PyPDF2.PdfReader(file)
                if pdf_reader.metadata:
                    result['metadata_found'] = dict(pdf_reader.metadata)
                    
                    # Check for sensitive metadata
                    sensitive_fields = ['/Creator', '/Producer', '/ModDate', '/CreationDate']
                    for field in sensitive_fields:
                        if field in result['metadata_found']:
                            result['issues'].append(f"Sensitive metadata found: {field}")
                            result['recommendations'].append(f"Remove {field} metadata")
        
        except ImportError:
            result['issues'].append("PyPDF2 not available for PDF metadata analysis")
        except Exception as e:
            result['issues'].append(f"PDF metadata analysis error: {str(e)}")
        
        return result
    
    def _analyze_office_metadata(self, file_path: str) -> Dict:
        """Analyze Office document metadata"""
        result = {'metadata_found': {}, 'issues': [], 'recommendations': []}
        
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                if 'docProps/core.xml' in zip_file.namelist():
                    core_xml = zip_file.read('docProps/core.xml')
                    root = ET.fromstring(core_xml)
                    
                    for child in root:
                        if child.text:
                            result['metadata_found'][child.tag.split('}')[-1]] = child.text
                    
                    # Check for sensitive metadata
                    sensitive_fields = ['creator', 'lastModifiedBy', 'created', 'modified']
                    for field in sensitive_fields:
                        if field in result['metadata_found']:
                            result['issues'].append(f"Sensitive metadata found: {field}")
                            result['recommendations'].append(f"Remove {field} metadata")
        
        except Exception as e:
            result['issues'].append(f"Office metadata analysis error: {str(e)}")
        
        return result
    
    def _analyze_image_metadata(self, file_path: str) -> Dict:
        """Analyze image metadata"""
        result = {'metadata_found': {}, 'issues': [], 'recommendations': []}
        
        try:
            with Image.open(file_path) as img:
                if hasattr(img, '_getexif') and img._getexif():
                    exif_data = img._getexif()
                    result['metadata_found']['exif'] = exif_data
                    
                    # Check for GPS data
                    if exif_data and 34853 in exif_data:
                        result['issues'].append("GPS location data found in image")
                        result['recommendations'].append("Remove GPS EXIF data for privacy")
                
                result['metadata_found']['format'] = img.format
                result['metadata_found']['size'] = img.size
                result['metadata_found']['mode'] = img.mode
        
        except Exception as e:
            result['issues'].append(f"Image metadata analysis error: {str(e)}")
        
        return result
    
    def _analyze_generic_metadata(self, file_path: str) -> Dict:
        """Analyze generic file metadata"""
        result = {'metadata_found': {}, 'issues': [], 'recommendations': []}
        
        stat_info = os.stat(file_path)
        result['metadata_found'] = {
            'size_bytes': stat_info.st_size,
            'created_time': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            'file_type': magic.from_file(file_path, mime=True)
        }
        
        return result
    
    def _validate_content(self, file_path: str, file_type: str) -> Dict:
        """Validate file content"""
        result = {
            'is_valid': True,
            'issues': []
        }
        
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Check for suspicious content patterns
            suspicious_patterns = [
                b'javascript:',
                b'vbscript:',
                b'<script',
                b'<iframe',
                b'<object',
                b'<embed'
            ]
            
            for pattern in suspicious_patterns:
                if pattern in content.lower():
                    result['issues'].append(f"Suspicious content pattern: {pattern.decode()}")
            
            # Check for binary content in text files
            file_extension = Path(file_path).suffix.lower()
            if file_extension in ['.txt', '.csv']:
                # Check for null bytes (binary content)
                if b'\x00' in content:
                    result['issues'].append("Binary content detected in text file")
            
            # Check for oversized content
            if len(content) > 100 * 1024 * 1024:  # 100MB
                result['issues'].append("File size exceeds recommended limit")
        
        except Exception as e:
            result['issues'].append(f"Content validation error: {str(e)}")
        
        return result
    
    def _check_policy_compliance(self, file_path: str, file_type: str) -> Dict:
        """Check if file complies with security policies"""
        result = {
            'is_compliant': True,
            'issues': [],
            'recommendations': []
        }
        
        if file_type not in self.security_policies:
            result['issues'].append(f"Unknown file type: {file_type}")
            return result
        
        policy = self.security_policies[file_type]
        
        # Check file size
        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        if file_size_mb > policy['max_size_mb']:
            result['is_compliant'] = False
            result['issues'].append(f"File size ({file_size_mb:.2f}MB) exceeds limit ({policy['max_size_mb']}MB)")
            result['recommendations'].append("Compress or split file")
        
        # Check file format
        file_extension = Path(file_path).suffix.lower()
        if file_extension not in policy['allowed_formats']:
            result['is_compliant'] = False
            result['issues'].append(f"File format {file_extension} not allowed for {file_type}")
            result['recommendations'].append(f"Convert to allowed format: {', '.join(policy['allowed_formats'])}")
        
        # Check for required encryption
        if policy['required_encryption']:
            result['recommendations'].append("File should be encrypted for security")
        
        return result
    
    def _calculate_security_score(self, verification_result: Dict) -> float:
        """Calculate overall security score (0-100)"""
        score = 100.0
        
        # Deduct points for each issue
        issue_penalties = {
            'integrity': 30,
            'malware': 40,
            'metadata': 15,
            'content': 20,
            'policy': 25
        }
        
        if not verification_result['integrity_check']:
            score -= issue_penalties['integrity']
        
        if not verification_result['malware_check']:
            score -= issue_penalties['malware']
        
        if not verification_result['metadata_check']:
            score -= issue_penalties['metadata']
        
        if not verification_result['content_check']:
            score -= issue_penalties['content']
        
        if not verification_result['policy_compliance']:
            score -= issue_penalties['policy']
        
        # Additional penalties for specific issues
        for issue in verification_result['issues_found']:
            if 'malware' in issue.lower():
                score -= 20
            elif 'executable' in issue.lower():
                score -= 30
            elif 'suspicious' in issue.lower():
                score -= 15
        
        return max(0.0, score)
    
    def _determine_verification_status(self, verification_result: Dict) -> str:
        """Determine verification status based on results"""
        if verification_result['security_score'] >= 80:
            return "VERIFIED"
        elif verification_result['security_score'] >= 60:
            return "PENDING"
        elif verification_result['security_score'] >= 40:
            return "QUARANTINED"
        else:
            return "FAILED"
    
    def _record_verification(self, verification_result: Dict):
        """Record verification in history"""
        self.verification_history.append(verification_result)
        logger.info(f"Verification recorded: {verification_result['file_name']} - {verification_result['verification_status']}")
    
    def get_verification_history(self, user_id: str = None) -> List[Dict]:
        """Get verification history"""
        if user_id:
            return [v for v in self.verification_history if v.get('user_id') == user_id]
        else:
            return self.verification_history.copy()
    
    def export_verification_report(self, verification_result: Dict, output_path: str):
        """Export detailed verification report"""
        report = {
            'verification_summary': {
                'timestamp': verification_result['timestamp'],
                'file_name': verification_result['file_name'],
                'file_type': verification_result['file_type'],
                'security_score': verification_result['security_score'],
                'verification_status': verification_result['verification_status']
            },
            'detailed_results': verification_result,
            'recommendations': verification_result['recommendations']
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Verification report exported to {output_path}")


# Example usage
if __name__ == "__main__":
    # Initialize file verification system
    verifier = FileVerificationSystem()
    
    # Test file verification
    test_file = "test_document.pdf"  # Replace with actual file
    
    if os.path.exists(test_file):
        # Verify file
        result = verifier.verify_file(test_file, "assignment", "user_123")
        
        print(f"File Verification Results:")
        print(f"Status: {result['verification_status']}")
        print(f"Security Score: {result['security_score']:.1f}/100")
        print(f"Integrity Check: {'PASS' if result['integrity_check'] else 'FAIL'}")
        print(f"Malware Check: {'PASS' if result['malware_check'] else 'FAIL'}")
        print(f"Metadata Check: {'PASS' if result['metadata_check'] else 'FAIL'}")
        
        if result['issues_found']:
            print(f"\nIssues Found:")
            for issue in result['issues_found']:
                print(f"- {issue}")
        
        if result['recommendations']:
            print(f"\nRecommendations:")
            for rec in result['recommendations']:
                print(f"- {rec}")
        
        # Export report
        verifier.export_verification_report(result, "file_verification_report.json")
    
    else:
        print(f"Test file {test_file} not found. Please provide a valid file for testing.") 