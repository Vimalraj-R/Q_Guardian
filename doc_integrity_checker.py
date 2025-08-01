import hashlib
import json
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Optional, Any
import os
import mimetypes
import magic
from pathlib import Path
import base64
import hmac
import secrets
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import zipfile
import xml.etree.ElementTree as ET
from PIL import Image
import io
import struct

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class DocumentIntegrityChecker:
    """
    Document Integrity & Privacy Scanner for academic documents
    Features:
    - Blockchain-based hashing for tamper detection
    - Metadata security check (removes hidden data leaks)
    - Policy compliance verification
    - Support for multiple document formats
    """
    
    def __init__(self, blockchain_private_key: str = None):
        self.blockchain_private_key = blockchain_private_key or secrets.token_hex(32)
        self.supported_formats = {
            '.pdf', '.docx', '.doc', '.txt', '.rtf', '.odt',
            '.jpg', '.jpeg', '.png', '.gif', '.bmp', '.tiff',
            '.xlsx', '.xls', '.csv', '.ppt', '.pptx'
        }
        
        # Privacy policies for different document types
        self.privacy_policies = {
            'exam_paper': {
                'allowed_metadata': ['title', 'author', 'date_created'],
                'forbidden_metadata': ['creator', 'producer', 'modify_date', 'create_date'],
                'max_file_size_mb': 50,
                'required_encryption': True
            },
            'assignment': {
                'allowed_metadata': ['title', 'author'],
                'forbidden_metadata': ['creator', 'producer', 'modify_date'],
                'max_file_size_mb': 25,
                'required_encryption': False
            },
            'grade_report': {
                'allowed_metadata': ['title', 'date_created'],
                'forbidden_metadata': ['creator', 'producer', 'author'],
                'max_file_size_mb': 10,
                'required_encryption': True
            }
        }
        
        # Initialize blockchain storage (simulated)
        self.blockchain_records = []
        
        logger.info("Document Integrity Checker initialized")
    
    def scan_document(self, file_path: str, document_type: str = "assignment") -> Dict:
        """
        Comprehensive document scan for integrity and privacy
        """
        logger.info(f"Scanning document: {file_path}")
        
        if not os.path.exists(file_path):
            raise FileNotFoundError(f"Document not found: {file_path}")
        
        # Initialize scan results
        scan_results = {
            'timestamp': datetime.now().isoformat(),
            'file_path': file_path,
            'document_type': document_type,
            'file_size_bytes': os.path.getsize(file_path),
            'file_hash': None,
            'integrity_check': False,
            'privacy_check': False,
            'compliance_check': False,
            'metadata_analysis': {},
            'security_issues': [],
            'recommendations': []
        }
        
        try:
            # 1. Generate blockchain hash
            file_hash = self._generate_blockchain_hash(file_path)
            scan_results['file_hash'] = file_hash
            
            # 2. Check document integrity
            integrity_result = self._check_document_integrity(file_path, file_hash)
            scan_results['integrity_check'] = integrity_result['is_valid']
            scan_results['security_issues'].extend(integrity_result['issues'])
            
            # 3. Analyze metadata for privacy
            metadata_result = self._analyze_metadata(file_path, document_type)
            scan_results['metadata_analysis'] = metadata_result
            scan_results['privacy_check'] = metadata_result['is_secure']
            scan_results['security_issues'].extend(metadata_result['issues'])
            
            # 4. Check policy compliance
            compliance_result = self._check_policy_compliance(file_path, document_type)
            scan_results['compliance_check'] = compliance_result['is_compliant']
            scan_results['security_issues'].extend(compliance_result['issues'])
            scan_results['recommendations'].extend(compliance_result['recommendations'])
            
            # 5. Generate overall security score
            scan_results['security_score'] = self._calculate_security_score(scan_results)
            
            # 6. Record in blockchain
            self._record_in_blockchain(scan_results)
            
            logger.info(f"Document scan completed. Security score: {scan_results['security_score']}")
            
        except Exception as e:
            logger.error(f"Error scanning document: {str(e)}")
            scan_results['security_issues'].append(f"Scan error: {str(e)}")
            scan_results['security_score'] = 0
        
        return scan_results
    
    def _generate_blockchain_hash(self, file_path: str) -> str:
        """
        Generate SHA-256 hash for blockchain recording
        """
        sha256_hash = hashlib.sha256()
        
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                sha256_hash.update(chunk)
        
        return sha256_hash.hexdigest()
    
    def _check_document_integrity(self, file_path: str, file_hash: str) -> Dict:
        """
        Check document integrity using blockchain verification
        """
        result = {
            'is_valid': True,
            'issues': [],
            'blockchain_verified': False
        }
        
        # Check if file hash exists in blockchain
        for record in self.blockchain_records:
            if record['file_hash'] == file_hash:
                result['blockchain_verified'] = True
                break
        
        # Check for file corruption
        try:
            with open(file_path, 'rb') as f:
                content = f.read()
            
            # Verify file structure based on type
            file_extension = Path(file_path).suffix.lower()
            
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
        
        except Exception as e:
            result['is_valid'] = False
            result['issues'].append(f"File corruption detected: {str(e)}")
        
        return result
    
    def _analyze_metadata(self, file_path: str, document_type: str) -> Dict:
        """
        Analyze document metadata for privacy and security
        """
        result = {
            'is_secure': True,
            'metadata_found': {},
            'issues': [],
            'recommendations': []
        }
        
        file_extension = Path(file_path).suffix.lower()
        
        try:
            if file_extension == '.pdf':
                result.update(self._analyze_pdf_metadata(file_path))
            elif file_extension in ['.docx', '.xlsx', '.pptx']:
                result.update(self._analyze_office_metadata(file_path))
            elif file_extension in ['.jpg', '.jpeg', '.png', '.gif']:
                result.update(self._analyze_image_metadata(file_path))
            else:
                result.update(self._analyze_generic_metadata(file_path))
        
        except Exception as e:
            result['issues'].append(f"Metadata analysis error: {str(e)}")
            result['is_secure'] = False
        
        return result
    
    def _analyze_pdf_metadata(self, file_path: str) -> Dict:
        """
        Analyze PDF metadata for privacy concerns
        """
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
        """
        Analyze Office document metadata
        """
        result = {'metadata_found': {}, 'issues': [], 'recommendations': []}
        
        try:
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                # Check for core.xml (contains metadata)
                if 'docProps/core.xml' in zip_file.namelist():
                    core_xml = zip_file.read('docProps/core.xml')
                    root = ET.fromstring(core_xml)
                    
                    # Extract metadata
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
        """
        Analyze image metadata (EXIF data)
        """
        result = {'metadata_found': {}, 'issues': [], 'recommendations': []}
        
        try:
            with Image.open(file_path) as img:
                # Check for EXIF data
                if hasattr(img, '_getexif') and img._getexif():
                    exif_data = img._getexif()
                    result['metadata_found']['exif'] = exif_data
                    
                    # Check for GPS data (location privacy)
                    if exif_data and 34853 in exif_data:  # GPSInfo
                        result['issues'].append("GPS location data found in image")
                        result['recommendations'].append("Remove GPS EXIF data for privacy")
                
                # Check image format and size
                result['metadata_found']['format'] = img.format
                result['metadata_found']['size'] = img.size
                result['metadata_found']['mode'] = img.mode
        
        except Exception as e:
            result['issues'].append(f"Image metadata analysis error: {str(e)}")
        
        return result
    
    def _analyze_generic_metadata(self, file_path: str) -> Dict:
        """
        Analyze generic file metadata
        """
        result = {'metadata_found': {}, 'issues': [], 'recommendations': []}
        
        # Basic file information
        stat_info = os.stat(file_path)
        result['metadata_found'] = {
            'size_bytes': stat_info.st_size,
            'created_time': datetime.fromtimestamp(stat_info.st_ctime).isoformat(),
            'modified_time': datetime.fromtimestamp(stat_info.st_mtime).isoformat(),
            'file_type': magic.from_file(file_path, mime=True)
        }
        
        return result
    
    def _check_policy_compliance(self, file_path: str, document_type: str) -> Dict:
        """
        Check if document complies with privacy policies
        """
        result = {
            'is_compliant': True,
            'issues': [],
            'recommendations': []
        }
        
        if document_type not in self.privacy_policies:
            result['issues'].append(f"Unknown document type: {document_type}")
            return result
        
        policy = self.privacy_policies[document_type]
        
        # Check file size
        file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
        if file_size_mb > policy['max_file_size_mb']:
            result['is_compliant'] = False
            result['issues'].append(f"File size ({file_size_mb:.2f}MB) exceeds limit ({policy['max_file_size_mb']}MB)")
            result['recommendations'].append("Compress or split document")
        
        # Check file format
        file_extension = Path(file_path).suffix.lower()
        if file_extension not in self.supported_formats:
            result['is_compliant'] = False
            result['issues'].append(f"Unsupported file format: {file_extension}")
            result['recommendations'].append("Convert to supported format")
        
        # Check for required encryption
        if policy['required_encryption']:
            # This would check if file is encrypted
            # For demo purposes, we'll assume encryption check
            result['recommendations'].append("Document should be encrypted for security")
        
        return result
    
    def _calculate_security_score(self, scan_results: Dict) -> float:
        """
        Calculate overall security score (0-100)
        """
        score = 100.0
        
        # Deduct points for each issue
        issue_penalties = {
            'integrity': 30,
            'privacy': 25,
            'compliance': 20,
            'metadata': 15,
            'corruption': 40
        }
        
        if not scan_results['integrity_check']:
            score -= issue_penalties['integrity']
        
        if not scan_results['privacy_check']:
            score -= issue_penalties['privacy']
        
        if not scan_results['compliance_check']:
            score -= issue_penalties['compliance']
        
        # Additional penalties for specific issues
        for issue in scan_results['security_issues']:
            if 'corruption' in issue.lower():
                score -= issue_penalties['corruption']
            elif 'metadata' in issue.lower():
                score -= issue_penalties['metadata']
        
        return max(0.0, score)
    
    def _record_in_blockchain(self, scan_results: Dict):
        """
        Record scan results in blockchain (simulated)
        """
        blockchain_record = {
            'timestamp': scan_results['timestamp'],
            'file_hash': scan_results['file_hash'],
            'security_score': scan_results['security_score'],
            'integrity_check': scan_results['integrity_check'],
            'privacy_check': scan_results['privacy_check'],
            'compliance_check': scan_results['compliance_check'],
            'document_type': scan_results['document_type'],
            'block_hash': self._generate_block_hash(scan_results)
        }
        
        self.blockchain_records.append(blockchain_record)
        logger.info(f"Recorded scan in blockchain: {blockchain_record['block_hash']}")
    
    def _generate_block_hash(self, scan_results: Dict) -> str:
        """
        Generate block hash for blockchain
        """
        block_data = f"{scan_results['timestamp']}{scan_results['file_hash']}{scan_results['security_score']}"
        return hashlib.sha256(block_data.encode()).hexdigest()
    
    def clean_document_metadata(self, file_path: str, output_path: str = None) -> str:
        """
        Clean document metadata for privacy
        """
        if output_path is None:
            output_path = file_path.replace('.', '_cleaned.')
        
        file_extension = Path(file_path).suffix.lower()
        
        try:
            if file_extension == '.pdf':
                return self._clean_pdf_metadata(file_path, output_path)
            elif file_extension in ['.docx', '.xlsx', '.pptx']:
                return self._clean_office_metadata(file_path, output_path)
            elif file_extension in ['.jpg', '.jpeg', '.png']:
                return self._clean_image_metadata(file_path, output_path)
            else:
                # For unsupported formats, just copy the file
                import shutil
                shutil.copy2(file_path, output_path)
                return output_path
        
        except Exception as e:
            logger.error(f"Error cleaning metadata: {str(e)}")
            raise
    
    def _clean_pdf_metadata(self, file_path: str, output_path: str) -> str:
        """
        Clean PDF metadata
        """
        try:
            import PyPDF2
            from PyPDF2 import PdfReader, PdfWriter
            
            reader = PdfReader(file_path)
            writer = PdfWriter()
            
            # Copy pages without metadata
            for page in reader.pages:
                writer.add_page(page)
            
            # Write cleaned PDF
            with open(output_path, 'wb') as output_file:
                writer.write(output_file)
            
            return output_path
        
        except ImportError:
            logger.warning("PyPDF2 not available, copying file without cleaning")
            import shutil
            shutil.copy2(file_path, output_path)
            return output_path
    
    def _clean_office_metadata(self, file_path: str, output_path: str) -> str:
        """
        Clean Office document metadata
        """
        import shutil
        import tempfile
        
        with tempfile.TemporaryDirectory() as temp_dir:
            # Extract document
            with zipfile.ZipFile(file_path, 'r') as zip_file:
                zip_file.extractall(temp_dir)
            
            # Remove metadata files
            metadata_files = ['docProps/core.xml', 'docProps/app.xml']
            for metadata_file in metadata_files:
                metadata_path = os.path.join(temp_dir, metadata_file)
                if os.path.exists(metadata_path):
                    os.remove(metadata_path)
            
            # Create cleaned document
            with zipfile.ZipFile(output_path, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                for root, dirs, files in os.walk(temp_dir):
                    for file in files:
                        file_path_in_zip = os.path.relpath(os.path.join(root, file), temp_dir)
                        zip_file.write(os.path.join(root, file), file_path_in_zip)
        
        return output_path
    
    def _clean_image_metadata(self, file_path: str, output_path: str) -> str:
        """
        Clean image metadata (EXIF data)
        """
        try:
            with Image.open(file_path) as img:
                # Create new image without EXIF data
                new_img = img.copy()
                
                # Save without metadata
                new_img.save(output_path, format=img.format, optimize=True)
            
            return output_path
        
        except Exception as e:
            logger.error(f"Error cleaning image metadata: {str(e)}")
            import shutil
            shutil.copy2(file_path, output_path)
            return output_path
    
    def get_blockchain_history(self, file_hash: str = None) -> List[Dict]:
        """
        Get blockchain history for a file or all records
        """
        if file_hash:
            return [record for record in self.blockchain_records if record['file_hash'] == file_hash]
        else:
            return self.blockchain_records.copy()
    
    def export_scan_report(self, scan_results: Dict, output_path: str):
        """
        Export detailed scan report
        """
        report = {
            'scan_summary': {
                'timestamp': scan_results['timestamp'],
                'file_path': scan_results['file_path'],
                'document_type': scan_results['document_type'],
                'security_score': scan_results['security_score'],
                'overall_status': 'PASS' if scan_results['security_score'] >= 70 else 'FAIL'
            },
            'detailed_results': scan_results,
            'blockchain_record': self.get_blockchain_history(scan_results['file_hash'])
        }
        
        with open(output_path, 'w') as f:
            json.dump(report, f, indent=2)
        
        logger.info(f"Scan report exported to {output_path}")


# Example usage
if __name__ == "__main__":
    # Initialize document integrity checker
    checker = DocumentIntegrityChecker()
    
    # Example document scan
    test_file = "sample_document.pdf"  # Replace with actual file
    
    if os.path.exists(test_file):
        # Scan document
        scan_results = checker.scan_document(test_file, "exam_paper")
        
        print(f"Document Scan Results:")
        print(f"Security Score: {scan_results['security_score']:.1f}/100")
        print(f"Integrity Check: {'PASS' if scan_results['integrity_check'] else 'FAIL'}")
        print(f"Privacy Check: {'PASS' if scan_results['privacy_check'] else 'FAIL'}")
        print(f"Compliance Check: {'PASS' if scan_results['compliance_check'] else 'FAIL'}")
        
        if scan_results['security_issues']:
            print(f"\nSecurity Issues Found:")
            for issue in scan_results['security_issues']:
                print(f"- {issue}")
        
        if scan_results['recommendations']:
            print(f"\nRecommendations:")
            for rec in scan_results['recommendations']:
                print(f"- {rec}")
        
        # Export report
        checker.export_scan_report(scan_results, "document_scan_report.json")
    
    else:
        print(f"Test file {test_file} not found. Please provide a valid document for testing.") 