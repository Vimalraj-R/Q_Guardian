import asyncio
import threading
import time
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any
import os
import signal
import sys
from dataclasses import dataclass
from enum import Enum
import docker
import kubernetes
from kubernetes import client, config
import yaml
import requests
import websockets
import queue
import multiprocessing as mp

# Import our modules
from quantum_anomaly_detector import QuantumAnomalyDetector
from federated_learning_system import FederatedLearningSystem
from doc_integrity_checker import DocumentIntegrityChecker
from zkp_authentication import ZKPAuthenticationSystem, BiometricType
from qguardian_dashboard import QGuardianDashboard

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class UserRole(Enum):
    ADMIN = "admin"
    TEACHER = "teacher"
    STUDENT = "student"
    SECURITY_OFFICER = "security_officer"

@dataclass
class SecurityEvent:
    """Security event data structure"""
    event_id: str
    timestamp: datetime
    event_type: str
    severity: str
    source_module: str
    user_id: Optional[str]
    institution: Optional[str]
    details: Dict
    risk_score: float

class MainIntegrationSystem:
    """
    Main Integration System for QGuardian Security Platform
    Orchestrates all modules in real-time with role-based access control
    """
    
    def __init__(self, config_path: str = "config.json"):
        self.config = self._load_config(config_path)
        self.running = False
        self.event_queue = queue.Queue()
        self.security_events = []
        self.active_sessions = {}
        
        # Initialize all modules
        self._initialize_modules()
        
        # Initialize role-based access control
        self._initialize_rbac()
        
        # Initialize deployment manager
        self._initialize_deployment_manager()
        
        logger.info("Main Integration System initialized")
    
    def _load_config(self, config_path: str) -> Dict:
        """Load configuration from file"""
        try:
            with open(config_path, 'r') as f:
                config = json.load(f)
        except FileNotFoundError:
            # Create default config
            config = {
                'system': {
                    'name': 'QGuardian Security System',
                    'version': '1.0.0',
                    'environment': 'production'
                },
                'modules': {
                    'quantum_anomaly_detector': {
                        'enabled': True,
                        'n_qubits': 4,
                        'n_layers': 3
                    },
                    'federated_learning': {
                        'enabled': True,
                        'num_institutions': 5,
                        'min_clients': 3
                    },
                    'document_integrity': {
                        'enabled': True,
                        'supported_formats': ['.pdf', '.docx', '.doc', '.txt']
                    },
                    'zkp_authentication': {
                        'enabled': True,
                        'session_timeout': 3600
                    },
                    'dashboard': {
                        'enabled': True,
                        'port': 8501
                    }
                },
                'deployment': {
                    'docker_enabled': True,
                    'kubernetes_enabled': False,
                    'replicas': 3
                },
                'security': {
                    'encryption_enabled': True,
                    'audit_logging': True,
                    'rate_limiting': True
                }
            }
            
            # Save default config
            with open(config_path, 'w') as f:
                json.dump(config, f, indent=2)
        
        return config
    
    def _initialize_modules(self):
        """Initialize all security modules"""
        logger.info("Initializing security modules...")
        
        # Initialize Quantum Anomaly Detector
        if self.config['modules']['quantum_anomaly_detector']['enabled']:
            self.quantum_detector = QuantumAnomalyDetector(
                n_qubits=self.config['modules']['quantum_anomaly_detector']['n_qubits'],
                n_layers=self.config['modules']['quantum_anomaly_detector']['n_layers']
            )
            logger.info("Quantum Anomaly Detector initialized")
        else:
            self.quantum_detector = None
        
        # Initialize Federated Learning System
        if self.config['modules']['federated_learning']['enabled']:
            self.federated_system = FederatedLearningSystem(
                num_institutions=self.config['modules']['federated_learning']['num_institutions']
            )
            logger.info("Federated Learning System initialized")
        else:
            self.federated_system = None
        
        # Initialize Document Integrity Checker
        if self.config['modules']['document_integrity']['enabled']:
            self.doc_checker = DocumentIntegrityChecker()
            logger.info("Document Integrity Checker initialized")
        else:
            self.doc_checker = None
        
        # Initialize ZKP Authentication System
        if self.config['modules']['zkp_authentication']['enabled']:
            self.auth_system = ZKPAuthenticationSystem()
            logger.info("ZKP Authentication System initialized")
        else:
            self.auth_system = None
        
        # Initialize Dashboard
        if self.config['modules']['dashboard']['enabled']:
            self.dashboard = QGuardianDashboard()
            logger.info("QGuardian Dashboard initialized")
        else:
            self.dashboard = None
    
    def _initialize_rbac(self):
        """Initialize role-based access control"""
        self.rbac_policies = {
            UserRole.ADMIN: {
                'permissions': ['all'],
                'data_access': ['all_logs', 'all_documents', 'all_users'],
                'actions': ['view', 'edit', 'delete', 'deploy', 'configure']
            },
            UserRole.SECURITY_OFFICER: {
                'permissions': ['security_events', 'anomaly_detection', 'document_scanning'],
                'data_access': ['security_logs', 'anomaly_reports', 'document_reports'],
                'actions': ['view', 'investigate', 'resolve']
            },
            UserRole.TEACHER: {
                'permissions': ['own_classes', 'student_data', 'document_upload'],
                'data_access': ['own_documents', 'own_students', 'own_reports'],
                'actions': ['view', 'upload', 'grade']
            },
            UserRole.STUDENT: {
                'permissions': ['own_data', 'document_submission'],
                'data_access': ['own_documents', 'own_grades'],
                'actions': ['view', 'submit']
            }
        }
        
        logger.info("Role-based access control initialized")
    
    def _initialize_deployment_manager(self):
        """Initialize deployment manager for Docker/Kubernetes"""
        self.deployment_manager = DeploymentManager(self.config['deployment'])
        logger.info("Deployment manager initialized")
    
    def start_system(self):
        """Start the main integration system"""
        logger.info("Starting QGuardian Security System...")
        self.running = True
        
        try:
            # Start all modules
            self._start_modules()
            
            # Start event processing
            self._start_event_processor()
            
            # Start monitoring
            self._start_monitoring()
            
            # Start dashboard if enabled
            if self.dashboard:
                self._start_dashboard()
            
            logger.info("QGuardian Security System started successfully")
            
            # Keep system running
            while self.running:
                time.sleep(1)
                
        except KeyboardInterrupt:
            logger.info("Shutdown signal received")
            self.stop_system()
        except Exception as e:
            logger.error(f"System error: {str(e)}")
            self.stop_system()
    
    def stop_system(self):
        """Stop the main integration system"""
        logger.info("Stopping QGuardian Security System...")
        self.running = False
        
        # Stop all modules
        self._stop_modules()
        
        # Stop event processing
        self._stop_event_processor()
        
        # Stop monitoring
        self._stop_monitoring()
        
        logger.info("QGuardian Security System stopped")
    
    def _start_modules(self):
        """Start all enabled modules"""
        if self.quantum_detector:
            # Start quantum anomaly detection in background
            threading.Thread(target=self._run_quantum_detection, daemon=True).start()
        
        if self.federated_system:
            # Start federated learning in background
            threading.Thread(target=self._run_federated_learning, daemon=True).start()
        
        if self.auth_system:
            # Start authentication monitoring
            threading.Thread(target=self._run_auth_monitoring, daemon=True).start()
    
    def _stop_modules(self):
        """Stop all modules"""
        # Modules will stop when self.running becomes False
        pass
    
    def _run_quantum_detection(self):
        """Run quantum anomaly detection in background"""
        while self.running:
            try:
                # Simulate behavioral data collection
                behavioral_data = self._collect_behavioral_data()
                
                if behavioral_data and self.quantum_detector:
                    # Detect anomalies
                    anomaly_report = self.quantum_detector.detect_anomaly(behavioral_data)
                    
                    # Process anomalies
                    self._process_anomaly_report(anomaly_report)
                
                time.sleep(30)  # Check every 30 seconds
                
            except Exception as e:
                logger.error(f"Quantum detection error: {str(e)}")
                time.sleep(60)
    
    def _run_federated_learning(self):
        """Run federated learning in background"""
        while self.running:
            try:
                if self.federated_system:
                    # Start federated training
                    self.federated_system.start_federated_training()
                
                time.sleep(300)  # Run every 5 minutes
                
            except Exception as e:
                logger.error(f"Federated learning error: {str(e)}")
                time.sleep(600)
    
    def _run_auth_monitoring(self):
        """Run authentication monitoring in background"""
        while self.running:
            try:
                if self.auth_system:
                    # Monitor authentication attempts
                    auth_stats = self.auth_system.get_authentication_stats()
                    
                    # Check for suspicious patterns
                    if auth_stats['success_rate'] < 80:
                        self._create_security_event(
                            "LOW_AUTH_SUCCESS_RATE",
                            "MEDIUM",
                            "authentication",
                            details=auth_stats
                        )
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Auth monitoring error: {str(e)}")
                time.sleep(120)
    
    def _collect_behavioral_data(self) -> Optional[pd.DataFrame]:
        """Collect behavioral data for anomaly detection"""
        try:
            # Simulate behavioral data collection
            # In a real system, this would collect actual user behavior data
            data = {
                'keystroke_timing_mean': [np.random.normal(200, 50) for _ in range(10)],
                'keystroke_timing_std': [np.random.normal(30, 10) for _ in range(10)],
                'login_time_pattern': [np.random.uniform(0, 24) for _ in range(10)],
                'file_access_frequency': [np.random.poisson(5) for _ in range(10)],
                'session_duration': [np.random.exponential(1800) for _ in range(10)],
                'typing_speed': [np.random.normal(60, 15) for _ in range(10)],
                'mouse_movement_pattern': [np.random.normal(100, 25) for _ in range(10)],
                'page_visit_sequence': [np.random.randint(1, 10) for _ in range(10)]
            }
            
            return pd.DataFrame(data)
        
        except Exception as e:
            logger.error(f"Behavioral data collection error: {str(e)}")
            return None
    
    def _process_anomaly_report(self, report: Dict):
        """Process anomaly detection report"""
        try:
            if report['anomalies_detected'] > 0:
                # Create security events for anomalies
                for result in report['detailed_results']:
                    if result['is_anomaly']:
                        self._create_security_event(
                            "ANOMALY_DETECTED",
                            "HIGH" if result['risk_score'] > 0.8 else "MEDIUM",
                            "quantum_detector",
                            details=result
                        )
            
            # Update system metrics
            self._update_system_metrics(report)
            
        except Exception as e:
            logger.error(f"Anomaly report processing error: {str(e)}")
    
    def _create_security_event(self, event_type: str, severity: str, 
                              source_module: str, user_id: str = None,
                              institution: str = None, details: Dict = None):
        """Create a security event"""
        event = SecurityEvent(
            event_id=f"event_{len(self.security_events) + 1}",
            timestamp=datetime.now(),
            event_type=event_type,
            severity=severity,
            source_module=source_module,
            user_id=user_id,
            institution=institution,
            details=details or {},
            risk_score=details.get('risk_score', 0.5) if details else 0.5
        )
        
        self.security_events.append(event)
        self.event_queue.put(event)
        
        logger.info(f"Security event created: {event_type} - {severity}")
    
    def _update_system_metrics(self, report: Dict):
        """Update system metrics"""
        # Update dashboard metrics if available
        if self.dashboard:
            self.dashboard.system_metrics['total_alerts'] += report.get('anomalies_detected', 0)
            self.dashboard.system_metrics['security_score'] = report.get('average_risk_score', 85.5) * 100
    
    def _start_event_processor(self):
        """Start event processing thread"""
        threading.Thread(target=self._process_events, daemon=True).start()
    
    def _stop_event_processor(self):
        """Stop event processing"""
        # Events will stop when self.running becomes False
        pass
    
    def _process_events(self):
        """Process security events"""
        while self.running:
            try:
                # Process events from queue
                while not self.event_queue.empty():
                    event = self.event_queue.get_nowait()
                    self._handle_security_event(event)
                
                time.sleep(1)
                
            except Exception as e:
                logger.error(f"Event processing error: {str(e)}")
                time.sleep(5)
    
    def _handle_security_event(self, event: SecurityEvent):
        """Handle a security event"""
        try:
            # Log event
            logger.info(f"Handling security event: {event.event_type}")
            
            # Route event based on type
            if event.event_type == "ANOMALY_DETECTED":
                self._handle_anomaly_event(event)
            elif event.event_type == "DOCUMENT_SCAN":
                self._handle_document_event(event)
            elif event.event_type == "AUTH_ATTEMPT":
                self._handle_auth_event(event)
            else:
                self._handle_generic_event(event)
            
            # Update dashboard if available
            if self.dashboard:
                self._update_dashboard_event(event)
            
        except Exception as e:
            logger.error(f"Event handling error: {str(e)}")
    
    def _handle_anomaly_event(self, event: SecurityEvent):
        """Handle anomaly detection event"""
        # Add to dashboard alerts
        if self.dashboard:
            alert = {
                'id': event.event_id,
                'timestamp': event.timestamp,
                'type': event.details.get('anomaly_type', 'UNKNOWN'),
                'institution': event.institution or 'Unknown',
                'severity': event.severity,
                'risk_score': event.risk_score,
                'status': 'ACTIVE',
                'description': f"Anomaly detected: {event.details.get('anomaly_type', 'Unknown')}"
            }
            self.dashboard.anomaly_alerts.append(alert)
    
    def _handle_document_event(self, event: SecurityEvent):
        """Handle document scanning event"""
        # Add to dashboard document scans
        if self.dashboard:
            scan = {
                'id': event.event_id,
                'timestamp': event.timestamp,
                'document_type': event.details.get('document_type', 'unknown'),
                'institution': event.institution or 'Unknown',
                'security_score': event.details.get('security_score', 0),
                'result': 'PASS' if event.details.get('security_score', 0) > 70 else 'FAIL',
                'file_size_mb': event.details.get('file_size_mb', 0),
                'integrity_check': event.details.get('integrity_check', False),
                'privacy_check': event.details.get('privacy_check', False)
            }
            self.dashboard.document_scans.append(scan)
    
    def _handle_auth_event(self, event: SecurityEvent):
        """Handle authentication event"""
        # Add to dashboard auth logs
        if self.dashboard:
            auth = {
                'id': event.event_id,
                'timestamp': event.timestamp,
                'user_id': event.user_id or 'unknown',
                'institution': event.institution or 'Unknown',
                'auth_type': event.details.get('auth_type', 'UNKNOWN'),
                'result': event.details.get('result', 'UNKNOWN'),
                'risk_score': event.risk_score,
                'session_duration': event.details.get('session_duration', 0),
                'ip_address': event.details.get('ip_address', '0.0.0.0')
            }
            self.dashboard.auth_logs.append(auth)
    
    def _handle_generic_event(self, event: SecurityEvent):
        """Handle generic security event"""
        logger.info(f"Generic event: {event.event_type} - {event.severity}")
    
    def _update_dashboard_event(self, event: SecurityEvent):
        """Update dashboard with event"""
        # Dashboard will be updated through the event handlers
        pass
    
    def _start_monitoring(self):
        """Start system monitoring"""
        threading.Thread(target=self._monitor_system_health, daemon=True).start()
    
    def _stop_monitoring(self):
        """Stop system monitoring"""
        # Monitoring will stop when self.running becomes False
        pass
    
    def _monitor_system_health(self):
        """Monitor system health"""
        while self.running:
            try:
                # Check module health
                health_status = self._check_module_health()
                
                # Log health status
                if not all(health_status.values()):
                    logger.warning("Some modules are unhealthy")
                
                time.sleep(60)  # Check every minute
                
            except Exception as e:
                logger.error(f"Health monitoring error: {str(e)}")
                time.sleep(120)
    
    def _check_module_health(self) -> Dict[str, bool]:
        """Check health of all modules"""
        health = {}
        
        # Check quantum detector
        health['quantum_detector'] = self.quantum_detector is not None
        
        # Check federated system
        health['federated_system'] = self.federated_system is not None
        
        # Check document checker
        health['document_checker'] = self.doc_checker is not None
        
        # Check auth system
        health['auth_system'] = self.auth_system is not None
        
        # Check dashboard
        health['dashboard'] = self.dashboard is not None
        
        return health
    
    def _start_dashboard(self):
        """Start the dashboard"""
        if self.dashboard:
            threading.Thread(target=self._run_dashboard, daemon=True).start()
    
    def _run_dashboard(self):
        """Run the dashboard"""
        try:
            import streamlit.web.cli as stcli
            import sys
            
            # Set up streamlit arguments
            sys.argv = [
                "streamlit", "run", "qguardian_dashboard.py",
                "--server.port", str(self.config['modules']['dashboard']['port']),
                "--server.address", "0.0.0.0"
            ]
            
            # Run dashboard
            stcli.main()
            
        except Exception as e:
            logger.error(f"Dashboard error: {str(e)}")
    
    def check_permission(self, user_id: str, role: UserRole, action: str, resource: str) -> bool:
        """Check if user has permission for action on resource"""
        if role not in self.rbac_policies:
            return False
        
        policy = self.rbac_policies[role]
        
        # Check if user has required permissions
        if 'all' in policy['permissions']:
            return True
        
        # Check specific permissions
        if action in policy['actions']:
            return True
        
        return False
    
    def get_user_data(self, user_id: str, role: UserRole) -> Dict:
        """Get user data based on role permissions"""
        if not self.check_permission(user_id, role, 'view', 'data'):
            return {'error': 'Access denied'}
        
        data = {}
        
        if role == UserRole.ADMIN:
            # Admin gets all data
            data = {
                'security_events': self.security_events,
                'system_metrics': self._get_system_metrics(),
                'module_status': self._check_module_health()
            }
        elif role == UserRole.SECURITY_OFFICER:
            # Security officer gets security-related data
            data = {
                'security_events': self.security_events,
                'anomaly_reports': self._get_anomaly_reports(),
                'auth_logs': self._get_auth_logs()
            }
        elif role == UserRole.TEACHER:
            # Teacher gets class-related data
            data = {
                'own_documents': self._get_user_documents(user_id),
                'own_students': self._get_user_students(user_id),
                'own_reports': self._get_user_reports(user_id)
            }
        elif role == UserRole.STUDENT:
            # Student gets own data
            data = {
                'own_documents': self._get_user_documents(user_id),
                'own_grades': self._get_user_grades(user_id)
            }
        
        return data
    
    def _get_system_metrics(self) -> Dict:
        """Get system metrics"""
        return {
            'total_events': len(self.security_events),
            'active_sessions': len(self.active_sessions),
            'module_health': self._check_module_health(),
            'uptime': self._get_uptime()
        }
    
    def _get_anomaly_reports(self) -> List[Dict]:
        """Get anomaly reports"""
        return [event for event in self.security_events 
                if event.event_type == "ANOMALY_DETECTED"]
    
    def _get_auth_logs(self) -> List[Dict]:
        """Get authentication logs"""
        return [event for event in self.security_events 
                if event.event_type == "AUTH_ATTEMPT"]
    
    def _get_user_documents(self, user_id: str) -> List[Dict]:
        """Get user documents"""
        # This would query the document database
        return []
    
    def _get_user_students(self, user_id: str) -> List[Dict]:
        """Get teacher's students"""
        # This would query the user database
        return []
    
    def _get_user_reports(self, user_id: str) -> List[Dict]:
        """Get user reports"""
        # This would query the reports database
        return []
    
    def _get_user_grades(self, user_id: str) -> List[Dict]:
        """Get user grades"""
        # This would query the grades database
        return []
    
    def _get_uptime(self) -> str:
        """Get system uptime"""
        # This would calculate actual uptime
        return "24h 30m 15s"


class DeploymentManager:
    """Manages Docker and Kubernetes deployments"""
    
    def __init__(self, config: Dict):
        self.config = config
        self.docker_client = None
        self.k8s_client = None
        
        if config.get('docker_enabled'):
            self._initialize_docker()
        
        if config.get('kubernetes_enabled'):
            self._initialize_kubernetes()
    
    def _initialize_docker(self):
        """Initialize Docker client"""
        try:
            self.docker_client = docker.from_env()
            logger.info("Docker client initialized")
        except Exception as e:
            logger.error(f"Docker initialization error: {str(e)}")
    
    def _initialize_kubernetes(self):
        """Initialize Kubernetes client"""
        try:
            config.load_kube_config()
            self.k8s_client = client.CoreV1Api()
            logger.info("Kubernetes client initialized")
        except Exception as e:
            logger.error(f"Kubernetes initialization error: {str(e)}")
    
    def deploy_docker(self, image_name: str, container_name: str) -> bool:
        """Deploy using Docker"""
        try:
            if not self.docker_client:
                return False
            
            # Pull image
            self.docker_client.images.pull(image_name)
            
            # Run container
            container = self.docker_client.containers.run(
                image_name,
                name=container_name,
                detach=True,
                ports={'8501/tcp': 8501}
            )
            
            logger.info(f"Docker container {container_name} deployed")
            return True
        
        except Exception as e:
            logger.error(f"Docker deployment error: {str(e)}")
            return False
    
    def deploy_kubernetes(self, deployment_config: Dict) -> bool:
        """Deploy using Kubernetes"""
        try:
            if not self.k8s_client:
                return False
            
            # Create deployment
            apps_v1 = client.AppsV1Api()
            deployment = client.V1Deployment(
                metadata=client.V1ObjectMeta(name=deployment_config['name']),
                spec=client.V1DeploymentSpec(
                    replicas=deployment_config.get('replicas', 1),
                    selector=client.V1LabelSelector(
                        match_labels={"app": deployment_config['name']}
                    ),
                    template=client.V1PodTemplateSpec(
                        metadata=client.V1ObjectMeta(
                            labels={"app": deployment_config['name']}
                        ),
                        spec=client.V1PodSpec(
                            containers=[
                                client.V1Container(
                                    name=deployment_config['name'],
                                    image=deployment_config['image']
                                )
                            ]
                        )
                    )
                )
            )
            
            apps_v1.create_namespaced_deployment(
                namespace="default",
                body=deployment
            )
            
            logger.info(f"Kubernetes deployment {deployment_config['name']} created")
            return True
        
        except Exception as e:
            logger.error(f"Kubernetes deployment error: {str(e)}")
            return False


# Main execution
if __name__ == "__main__":
    # Create and start the main integration system
    system = MainIntegrationSystem()
    
    # Set up signal handlers for graceful shutdown
    def signal_handler(signum, frame):
        logger.info("Received shutdown signal")
        system.stop_system()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    # Start the system
    system.start_system() 