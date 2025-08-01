import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import json
import time
import threading
from datetime import datetime, timedelta
from typing import Dict, List, Optional
import asyncio
import websockets
import logging
import os
from pathlib import Path
import hashlib
import base64

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class QGuardianProfessionalDashboard:
    """
    Professional QGuardian Security Dashboard
    Features:
    - Role-based access control (Admin, Security Officer, Teacher, Student)
    - File upload and verification system
    - Real-time security monitoring
    - Clean, professional UI design
    - Classified information handling
    """
    
    def __init__(self):
        self.anomaly_alerts = []
        self.document_scans = []
        self.federated_nodes = []
        self.auth_logs = []
        self.uploaded_files = []
        self.system_metrics = {
            'total_alerts': 0,
            'security_score': 85.5,
            'active_sessions': 42,
            'documents_scanned': 156,
            'federated_accuracy': 94.2,
            'files_verified': 89,
            'threats_blocked': 23
        }
        
        # Initialize demo data
        self._initialize_demo_data()
        
        logger.info("QGuardian Professional Dashboard initialized")
    
    def _initialize_demo_data(self):
        """Initialize professional demo data"""
        
        # Anomaly alerts with classification
        alert_types = ['SUSPICIOUS_LOGIN', 'UNUSUAL_FILE_ACCESS', 'EXAM_TAMPERING', 'BEHAVIORAL_ANOMALY']
        institutions = ['Stanford_University', 'MIT_Institute', 'Harvard_College', 'Berkeley_University']
        classifications = ['CONFIDENTIAL', 'SECRET', 'TOP_SECRET', 'PUBLIC']
        
        for i in range(20):
            alert = {
                'id': f"alert_{i+1}",
                'timestamp': datetime.now() - timedelta(hours=np.random.randint(1, 72)),
                'type': np.random.choice(alert_types),
                'institution': np.random.choice(institutions),
                'severity': np.random.choice(['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']),
                'classification': np.random.choice(classifications),
                'risk_score': np.random.uniform(0.3, 0.95),
                'status': np.random.choice(['ACTIVE', 'RESOLVED', 'INVESTIGATING']),
                'description': f"Anomaly detected in {np.random.choice(['login', 'file_access', 'exam_system'])}",
                'assigned_to': np.random.choice(['Security_Team', 'Admin', 'Unassigned']),
                'priority': np.random.choice(['LOW', 'MEDIUM', 'HIGH', 'URGENT'])
            }
            self.anomaly_alerts.append(alert)
        
        # Document scans with verification status
        doc_types = ['exam_paper', 'assignment', 'grade_report', 'research_paper', 'certificate']
        verification_status = ['VERIFIED', 'PENDING', 'FAILED', 'QUARANTINED']
        
        for i in range(50):
            scan = {
                'id': f"scan_{i+1}",
                'timestamp': datetime.now() - timedelta(hours=np.random.randint(1, 168)),
                'document_type': np.random.choice(doc_types),
                'institution': np.random.choice(institutions),
                'security_score': np.random.uniform(60, 100),
                'verification_status': np.random.choice(verification_status, p=[0.7, 0.2, 0.08, 0.02]),
                'file_size_mb': np.random.uniform(0.1, 25),
                'integrity_check': np.random.choice([True, False], p=[0.9, 0.1]),
                'privacy_check': np.random.choice([True, False], p=[0.85, 0.15]),
                'uploaded_by': f"user_{np.random.randint(1000, 9999)}",
                'file_hash': hashlib.sha256(f"file_{i}".encode()).hexdigest()[:16]
            }
            self.document_scans.append(scan)
        
        # Federated nodes with detailed status
        node_statuses = ['ONLINE', 'TRAINING', 'OFFLINE', 'SYNCING', 'MAINTENANCE']
        
        for i, institution in enumerate(institutions):
            node = {
                'institution': institution,
                'status': np.random.choice(node_statuses),
                'accuracy': np.random.uniform(85, 98),
                'data_samples': np.random.randint(500, 2000),
                'last_sync': datetime.now() - timedelta(minutes=np.random.randint(5, 60)),
                'privacy_epsilon': np.random.uniform(0.5, 2.0),
                'training_rounds': np.random.randint(1, 15),
                'security_level': np.random.choice(['BASIC', 'ENHANCED', 'MAXIMUM']),
                'uptime_percentage': np.random.uniform(95, 99.9)
            }
            self.federated_nodes.append(node)
        
        # Authentication logs with detailed info
        auth_types = ['KEYSTROKE', 'VOICE', 'BEHAVIOR', 'MULTI_MODAL', 'FACE_RECOGNITION']
        auth_results = ['SUCCESS', 'FAILED', 'TIMEOUT', 'BLOCKED']
        
        for i in range(100):
            auth = {
                'id': f"auth_{i+1}",
                'timestamp': datetime.now() - timedelta(minutes=np.random.randint(1, 1440)),
                'user_id': f"user_{np.random.randint(1000, 9999)}",
                'institution': np.random.choice(institutions),
                'auth_type': np.random.choice(auth_types),
                'result': np.random.choice(auth_results, p=[0.85, 0.12, 0.02, 0.01]),
                'risk_score': np.random.uniform(0.1, 0.9),
                'session_duration': np.random.randint(300, 3600),
                'ip_address': f"192.168.{np.random.randint(1, 255)}.{np.random.randint(1, 255)}",
                'device_info': f"Device_{np.random.randint(1, 100)}",
                'location': f"Location_{np.random.randint(1, 50)}"
            }
            self.auth_logs.append(auth)
    
    def run_dashboard(self):
        """Run the professional dashboard"""
        st.set_page_config(
            page_title="QGuardian Security Dashboard",
            page_icon="🛡️",
            layout="wide",
            initial_sidebar_state="expanded"
        )
        
        # Custom CSS for professional look
        st.markdown("""
        <style>
        .main-header {
            background: linear-gradient(90deg, #1f4e79 0%, #2980b9 100%);
            padding: 1rem;
            border-radius: 10px;
            color: white;
            margin-bottom: 2rem;
        }
        .metric-card {
            background: white;
            padding: 1rem;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            border-left: 4px solid #2980b9;
        }
        .alert-card {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 1rem;
            margin: 0.5rem 0;
        }
        .success-card {
            background: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 8px;
            padding: 1rem;
            margin: 0.5rem 0;
        }
        .warning-card {
            background: #fff3cd;
            border: 1px solid #ffeaa7;
            border-radius: 8px;
            padding: 1rem;
            margin: 0.5rem 0;
        }
        .danger-card {
            background: #f8d7da;
            border: 1px solid #f5c6cb;
            border-radius: 8px;
            padding: 1rem;
            margin: 0.5rem 0;
        }
        </style>
        """, unsafe_allow_html=True)
        
        # Main header
        st.markdown("""
        <div class="main-header">
            <h1>🛡️ QGuardian Security Dashboard</h1>
            <p>Professional Academic Security Monitoring System</p>
        </div>
        """, unsafe_allow_html=True)
        
        # Sidebar with role-based access
        self._create_professional_sidebar()
        
        # Main dashboard content
        self._show_dashboard_content()
    
    def _create_professional_sidebar(self):
        """Create professional sidebar with role-based access"""
        st.sidebar.header("🔧 Dashboard Controls")
        
        # Role selection
        st.sidebar.subheader("👤 User Role")
        user_role = st.sidebar.selectbox(
            "Select your role",
            ["Admin", "Security Officer", "Teacher", "Student"],
            index=0
        )
        
        # Time filter
        st.sidebar.subheader("⏰ Time Range")
        time_range = st.sidebar.selectbox(
            "Select time range",
            ["Last 24 hours", "Last 7 days", "Last 30 days", "All time"],
            index=1
        )
        
        # Classification filter
        st.sidebar.subheader("🔒 Classification Level")
        classification_level = st.sidebar.selectbox(
            "Select classification level",
            ["All Levels", "PUBLIC", "CONFIDENTIAL", "SECRET", "TOP_SECRET"],
            index=0
        )
        
        # Institution filter
        st.sidebar.subheader("🏫 Institution Filter")
        institutions = ['All Institutions', 'Stanford_University', 'MIT_Institute', 'Harvard_College', 'Berkeley_University']
        selected_institution = st.sidebar.selectbox("Select institution", institutions)
        
        # Alert severity filter
        st.sidebar.subheader("🚨 Alert Severity")
        severity_levels = ['All Severities', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        selected_severity = st.sidebar.selectbox("Select severity", severity_levels)
        
        # File upload section
        st.sidebar.subheader("📁 File Upload & Verification")
        uploaded_file = st.sidebar.file_uploader(
            "Upload document for verification",
            type=['pdf', 'docx', 'doc', 'txt', 'jpg', 'png'],
            help="Upload academic documents for security verification"
        )
        
        if uploaded_file is not None:
            self._handle_file_upload(uploaded_file)
        
        # Auto-refresh
        st.sidebar.subheader("🔄 Auto Refresh")
        auto_refresh = st.sidebar.checkbox("Enable auto-refresh", value=True)
        refresh_interval = st.sidebar.slider("Refresh interval (seconds)", 5, 60, 30)
        
        if auto_refresh:
            st.sidebar.info(f"Auto-refreshing every {refresh_interval} seconds")
        
        # Export data
        st.sidebar.subheader("📊 Export Data")
        if st.sidebar.button("Export Dashboard Data"):
            self._export_dashboard_data()
        
        # Store filters in session state
        st.session_state.user_role = user_role
        st.session_state.time_range = time_range
        st.session_state.classification_level = classification_level
        st.session_state.selected_institution = selected_institution
        st.session_state.selected_severity = selected_severity
    
    def _handle_file_upload(self, uploaded_file):
        """Handle file upload and verification"""
        try:
            # Save uploaded file
            file_path = f"uploads/{uploaded_file.name}"
            os.makedirs("uploads", exist_ok=True)
            
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            # Verify file
            verification_result = self._verify_uploaded_file(file_path, uploaded_file.name)
            
            # Add to uploaded files list
            self.uploaded_files.append({
                'name': uploaded_file.name,
                'size': uploaded_file.size,
                'type': uploaded_file.type,
                'upload_time': datetime.now(),
                'verification_result': verification_result,
                'file_path': file_path
            })
            
            st.sidebar.success(f"✅ File '{uploaded_file.name}' uploaded and verified!")
            
        except Exception as e:
            st.sidebar.error(f"❌ File upload failed: {str(e)}")
    
    def _verify_uploaded_file(self, file_path: str, filename: str) -> Dict:
        """Verify uploaded file for security"""
        try:
            # Calculate file hash
            with open(file_path, 'rb') as f:
                file_content = f.read()
                file_hash = hashlib.sha256(file_content).hexdigest()
            
            # Basic security checks
            file_size_mb = len(file_content) / (1024 * 1024)
            file_extension = Path(filename).suffix.lower()
            
            # Security assessment
            security_score = 100.0
            
            # Check file size
            if file_size_mb > 50:
                security_score -= 20
            
            # Check file type
            allowed_extensions = ['.pdf', '.docx', '.doc', '.txt', '.jpg', '.png']
            if file_extension not in allowed_extensions:
                security_score -= 30
            
            # Check for suspicious content (simplified)
            if b'virus' in file_content.lower() or b'malware' in file_content.lower():
                security_score -= 50
            
            # Determine verification status
            if security_score >= 80:
                status = "VERIFIED"
            elif security_score >= 60:
                status = "PENDING"
            else:
                status = "FAILED"
            
            return {
                'security_score': security_score,
                'file_hash': file_hash,
                'status': status,
                'file_size_mb': file_size_mb,
                'file_type': file_extension,
                'verification_time': datetime.now().isoformat()
            }
            
        except Exception as e:
            return {
                'security_score': 0,
                'file_hash': '',
                'status': 'FAILED',
                'error': str(e),
                'verification_time': datetime.now().isoformat()
            }
    
    def _show_dashboard_content(self):
        """Show main dashboard content"""
        
        # Top metrics row
        self._show_top_metrics()
        
        # Main content area
        col1, col2 = st.columns([2, 1])
        
        with col1:
            # Security overview
            self._show_security_overview()
            
            # Anomaly alerts
            self._show_anomaly_alerts()
            
            # Document verification
            self._show_document_verification()
        
        with col2:
            # Federated nodes
            self._show_federated_nodes()
            
            # Authentication logs
            self._show_auth_logs()
            
            # File upload status
            self._show_file_upload_status()
        
        # Bottom section
        self._show_detailed_analytics()
    
    def _show_top_metrics(self):
        """Show top-level security metrics"""
        st.subheader("📊 Security Overview")
        
        # Create metric cards
        col1, col2, col3, col4 = st.columns(4)
        
        with col1:
            st.markdown(f"""
            <div class="metric-card">
                <h3>🛡️ Security Score</h3>
                <h2>{self.system_metrics['security_score']:.1f}%</h2>
                <p>Overall system security</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
            <div class="metric-card">
                <h3>🚨 Active Alerts</h3>
                <h2>{self.system_metrics['total_alerts']}</h2>
                <p>Security incidents</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown(f"""
            <div class="metric-card">
                <h3>📁 Files Verified</h3>
                <h2>{self.system_metrics['files_verified']}</h2>
                <p>Documents processed</p>
            </div>
            """, unsafe_allow_html=True)
        
        with col4:
            st.markdown(f"""
            <div class="metric-card">
                <h3>🛑 Threats Blocked</h3>
                <h2>{self.system_metrics['threats_blocked']}</h2>
                <p>Security threats</p>
            </div>
            """, unsafe_allow_html=True)
    
    def _show_security_overview(self):
        """Show security overview with gauge"""
        st.subheader("🛡️ Security Status")
        
        # Security score gauge
        fig = go.Figure(go.Indicator(
            mode="gauge+number+delta",
            value=self.system_metrics['security_score'],
            domain={'x': [0, 1], 'y': [0, 1]},
            title={'text': "System Security Score"},
            delta={'reference': 80},
            gauge={
                'axis': {'range': [None, 100]},
                'bar': {'color': "darkblue"},
                'steps': [
                    {'range': [0, 50], 'color': "lightgray"},
                    {'range': [50, 80], 'color': "yellow"},
                    {'range': [80, 100], 'color': "green"}
                ],
                'threshold': {
                    'line': {'color': "red", 'width': 4},
                    'thickness': 0.75,
                    'value': 90
                }
            }
        ))
        fig.update_layout(height=300)
        st.plotly_chart(fig, use_container_width=True)
    
    def _show_anomaly_alerts(self):
        """Show classified anomaly alerts"""
        st.subheader("🚨 Security Alerts")
        
        # Filter alerts based on user role and classification
        filtered_alerts = self._filter_alerts()
        
        if filtered_alerts:
            # Create alert cards
            for alert in filtered_alerts[:10]:  # Show top 10
                alert_color = self._get_alert_color(alert['severity'])
                classification_badge = f"🔒 {alert['classification']}"
                
                st.markdown(f"""
                <div class="{alert_color}-card">
                    <h4>{alert['type']} - {alert['institution']}</h4>
                    <p><strong>Severity:</strong> {alert['severity']} | <strong>Risk Score:</strong> {alert['risk_score']:.2f}</p>
                    <p><strong>Classification:</strong> {classification_badge}</p>
                    <p><strong>Status:</strong> {alert['status']} | <strong>Assigned:</strong> {alert['assigned_to']}</p>
                    <p><strong>Description:</strong> {alert['description']}</p>
                    <p><strong>Time:</strong> {alert['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No alerts matching current filters")
        
        # Alert statistics
        st.subheader("📈 Alert Statistics")
        alert_stats = pd.DataFrame(filtered_alerts)
        if not alert_stats.empty:
            fig = px.pie(
                alert_stats, 
                names='severity', 
                title="Alert Severity Distribution",
                color_discrete_map={
                    'LOW': 'green',
                    'MEDIUM': 'yellow',
                    'HIGH': 'orange',
                    'CRITICAL': 'red'
                }
            )
            st.plotly_chart(fig, use_container_width=True)
    
    def _show_document_verification(self):
        """Show document verification status"""
        st.subheader("📄 Document Verification")
        
        # Filter documents based on user role
        filtered_docs = self._filter_documents()
        
        if filtered_docs:
            # Create document status cards
            for doc in filtered_docs[:5]:  # Show top 5
                status_color = self._get_document_status_color(doc['verification_status'])
                
                st.markdown(f"""
                <div class="{status_color}-card">
                    <h4>{doc['document_type'].title()} - {doc['institution']}</h4>
                    <p><strong>Status:</strong> {doc['verification_status']} | <strong>Security Score:</strong> {doc['security_score']:.1f}%</p>
                    <p><strong>File Size:</strong> {doc['file_size_mb']:.2f} MB | <strong>Hash:</strong> {doc['file_hash']}</p>
                    <p><strong>Integrity:</strong> {'✅ PASS' if doc['integrity_check'] else '❌ FAIL'} | <strong>Privacy:</strong> {'✅ PASS' if doc['privacy_check'] else '❌ FAIL'}</p>
                    <p><strong>Uploaded by:</strong> {doc['uploaded_by']} | <strong>Time:</strong> {doc['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}</p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No documents matching current filters")
    
    def _show_federated_nodes(self):
        """Show federated learning nodes"""
        st.subheader("🌐 Federated Learning Nodes")
        
        for node in self.federated_nodes:
            status_icon = "🟢" if node['status'] == 'ONLINE' else "🟡" if node['status'] == 'TRAINING' else "🔴"
            
            with st.expander(f"{status_icon} {node['institution']}"):
                col1, col2 = st.columns(2)
                with col1:
                    st.write(f"**Status:** {node['status']}")
                    st.write(f"**Accuracy:** {node['accuracy']:.1f}%")
                    st.write(f"**Data Samples:** {node['data_samples']:,}")
                with col2:
                    st.write(f"**Last Sync:** {node['last_sync'].strftime('%H:%M:%S')}")
                    st.write(f"**Privacy ε:** {node['privacy_epsilon']:.2f}")
                    st.write(f"**Uptime:** {node['uptime_percentage']:.1f}%")
                
                # Progress bar for accuracy
                st.progress(node['accuracy'] / 100)
    
    def _show_auth_logs(self):
        """Show authentication logs"""
        st.subheader("🔐 Authentication Logs")
        
        # Filter auth logs
        filtered_auths = self._filter_auth_logs()
        
        if filtered_auths:
            # Show recent auth attempts
            for auth in filtered_auths[:5]:
                result_color = "success" if auth['result'] == 'SUCCESS' else "danger"
                
                st.markdown(f"""
                <div class="{result_color}-card">
                    <p><strong>User:</strong> {auth['user_id']} | <strong>Type:</strong> {auth['auth_type']}</p>
                    <p><strong>Result:</strong> {auth['result']} | <strong>Risk:</strong> {auth['risk_score']:.2f}</p>
                    <p><strong>IP:</strong> {auth['ip_address']} | <strong>Device:</strong> {auth['device_info']}</p>
                    <p><strong>Time:</strong> {auth['timestamp'].strftime('%H:%M:%S')}</p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No authentication logs matching filters")
    
    def _show_file_upload_status(self):
        """Show file upload status"""
        st.subheader("📁 File Upload Status")
        
        if self.uploaded_files:
            for file_info in self.uploaded_files[-3:]:  # Show last 3
                result = file_info['verification_result']
                status_color = self._get_document_status_color(result['status'])
                
                st.markdown(f"""
                <div class="{status_color}-card">
                    <h4>{file_info['name']}</h4>
                    <p><strong>Status:</strong> {result['status']} | <strong>Score:</strong> {result['security_score']:.1f}%</p>
                    <p><strong>Size:</strong> {file_info['size'] / 1024:.1f} KB | <strong>Type:</strong> {file_info['type']}</p>
                    <p><strong>Upload Time:</strong> {file_info['upload_time'].strftime('%H:%M:%S')}</p>
                </div>
                """, unsafe_allow_html=True)
        else:
            st.info("No files uploaded yet")
    
    def _show_detailed_analytics(self):
        """Show detailed analytics"""
        st.subheader("🔍 Detailed Analytics")
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("🚨 Alert Analysis")
            
            # Alert by institution
            alert_df = pd.DataFrame(self.anomaly_alerts)
            if not alert_df.empty:
                institution_alerts = alert_df['institution'].value_counts()
                fig = px.bar(
                    x=institution_alerts.index,
                    y=institution_alerts.values,
                    title="Alerts by Institution"
                )
                st.plotly_chart(fig, use_container_width=True)
        
        with col2:
            st.subheader("📄 Document Analysis")
            
            # Document scan results by type
            scan_df = pd.DataFrame(self.document_scans)
            if not scan_df.empty:
                doc_results = scan_df.groupby(['document_type', 'verification_status']).size().unstack(fill_value=0)
                fig = px.bar(
                    doc_results,
                    title="Document Verification Results by Type"
                )
                st.plotly_chart(fig, use_container_width=True)
    
    def _filter_alerts(self):
        """Filter alerts based on user role and classification"""
        alerts = self.anomaly_alerts.copy()
        
        # Filter by classification level
        if st.session_state.classification_level != "All Levels":
            alerts = [a for a in alerts if a['classification'] == st.session_state.classification_level]
        
        # Filter by institution
        if st.session_state.selected_institution != "All Institutions":
            alerts = [a for a in alerts if a['institution'] == st.session_state.selected_institution]
        
        # Filter by severity
        if st.session_state.selected_severity != "All Severities":
            alerts = [a for a in alerts if a['severity'] == st.session_state.selected_severity]
        
        # Filter by time range
        if st.session_state.time_range == "Last 24 hours":
            cutoff = datetime.now() - timedelta(hours=24)
            alerts = [a for a in alerts if a['timestamp'] > cutoff]
        elif st.session_state.time_range == "Last 7 days":
            cutoff = datetime.now() - timedelta(days=7)
            alerts = [a for a in alerts if a['timestamp'] > cutoff]
        elif st.session_state.time_range == "Last 30 days":
            cutoff = datetime.now() - timedelta(days=30)
            alerts = [a for a in alerts if a['timestamp'] > cutoff]
        
        return alerts
    
    def _filter_documents(self):
        """Filter documents based on user role"""
        docs = self.document_scans.copy()
        
        # Filter by institution
        if st.session_state.selected_institution != "All Institutions":
            docs = [d for d in docs if d['institution'] == st.session_state.selected_institution]
        
        return docs
    
    def _filter_auth_logs(self):
        """Filter authentication logs"""
        auths = self.auth_logs.copy()
        
        # Filter by institution
        if st.session_state.selected_institution != "All Institutions":
            auths = [a for a in auths if a['institution'] == st.session_state.selected_institution]
        
        return auths
    
    def _get_alert_color(self, severity):
        """Get CSS class for alert severity"""
        if severity == 'CRITICAL':
            return 'danger'
        elif severity == 'HIGH':
            return 'warning'
        elif severity == 'MEDIUM':
            return 'alert'
        else:
            return 'success'
    
    def _get_document_status_color(self, status):
        """Get CSS class for document status"""
        if status == 'VERIFIED':
            return 'success'
        elif status == 'PENDING':
            return 'warning'
        elif status == 'FAILED':
            return 'danger'
        else:
            return 'alert'
    
    def _export_dashboard_data(self):
        """Export dashboard data"""
        export_data = {
            'timestamp': datetime.now().isoformat(),
            'anomaly_alerts': self.anomaly_alerts,
            'document_scans': self.document_scans,
            'federated_nodes': self.federated_nodes,
            'auth_logs': self.auth_logs,
            'uploaded_files': self.uploaded_files,
            'system_metrics': self.system_metrics
        }
        
        # Convert to JSON
        json_data = json.dumps(export_data, indent=2, default=str)
        
        # Create download button
        st.download_button(
            label="📥 Download Dashboard Data",
            data=json_data,
            file_name=f"qguardian_dashboard_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )


# Run dashboard
if __name__ == "__main__":
    dashboard = QGuardianProfessionalDashboard()
    dashboard.run_dashboard() 