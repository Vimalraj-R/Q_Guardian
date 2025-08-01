import pennylane as qml
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import torch
import torch.nn as nn
import json
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import hashlib

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class QuantumAnomalyDetector:
    """
    Quantum Anomaly Detector using PennyLane-based variational quantum neural network
    for detecting unusual academic activities (fake logins, unusual file access, exam tampering)
    """
    
    def __init__(self, n_qubits: int = 4, n_layers: int = 3, n_features: int = 8):
        self.n_qubits = n_qubits
        self.n_layers = n_layers
        self.n_features = n_features
        self.device = qml.device("default.qubit", wires=n_qubits)
        self.scaler = StandardScaler()
        self.model_params = None
        self.anomaly_threshold = 0.7
        self.training_history = []
        
        # Initialize quantum circuit
        self.qnode = qml.QNode(self.quantum_circuit, self.device)
        
        # Behavioral biometric features
        self.feature_names = [
            'keystroke_timing_mean',
            'keystroke_timing_std',
            'login_time_pattern',
            'file_access_frequency',
            'session_duration',
            'typing_speed',
            'mouse_movement_pattern',
            'page_visit_sequence'
        ]
        
        logger.info(f"Quantum Anomaly Detector initialized with {n_qubits} qubits, {n_layers} layers")
    
    def quantum_circuit(self, inputs: np.ndarray, weights: np.ndarray) -> np.ndarray:
        """
        Variational quantum circuit for anomaly detection
        """
        # Encode classical data into quantum state
        for i in range(self.n_qubits):
            qml.RY(inputs[i], wires=i)
        
        # Variational layers
        for layer in range(self.n_layers):
            # Rotations
            for i in range(self.n_qubits):
                qml.Rot(*weights[layer, i, :3], wires=i)
            
            # Entangling layer
            for i in range(self.n_qubits - 1):
                qml.CNOT(wires=[i, i + 1])
            qml.CNOT(wires=[self.n_qubits - 1, 0])
        
        # Measurement
        return [qml.expval(qml.PauliZ(i)) for i in range(self.n_qubits)]
    
    def preprocess_behavioral_data(self, data: pd.DataFrame) -> np.ndarray:
        """
        Preprocess behavioral biometric data for quantum circuit
        """
        # Extract relevant features
        features = []
        for _, row in data.iterrows():
            feature_vector = [
                row.get('keystroke_timing_mean', 0.0),
                row.get('keystroke_timing_std', 0.0),
                row.get('login_time_pattern', 0.0),
                row.get('file_access_frequency', 0.0),
                row.get('session_duration', 0.0),
                row.get('typing_speed', 0.0),
                row.get('mouse_movement_pattern', 0.0),
                row.get('page_visit_sequence', 0.0)
            ]
            features.append(feature_vector)
        
        features = np.array(features)
        
        # Normalize features
        if len(features) > 0:
            features = self.scaler.fit_transform(features)
        
        # Pad or truncate to match n_qubits
        if features.shape[1] < self.n_qubits:
            padding = np.zeros((features.shape[0], self.n_qubits - features.shape[1]))
            features = np.hstack([features, padding])
        elif features.shape[1] > self.n_qubits:
            features = features[:, :self.n_qubits]
        
        return features
    
    def cost_function(self, weights: np.ndarray, X: np.ndarray, y: np.ndarray) -> float:
        """
        Cost function for training the quantum model
        """
        predictions = []
        for x in X:
            pred = self.qnode(x, weights)
            predictions.append(np.mean(pred))
        
        predictions = np.array(predictions)
        
        # Binary cross-entropy loss
        epsilon = 1e-15
        predictions = np.clip(predictions, epsilon, 1 - epsilon)
        loss = -np.mean(y * np.log(predictions) + (1 - y) * np.log(1 - predictions))
        
        return loss
    
    def train(self, training_data: pd.DataFrame, labels: np.ndarray, 
              learning_rate: float = 0.01, epochs: int = 100) -> Dict:
        """
        Train the quantum anomaly detector
        """
        logger.info("Starting quantum model training...")
        
        # Preprocess data
        X = self.preprocess_behavioral_data(training_data)
        
        # Initialize weights
        self.model_params = np.random.rand(self.n_layers, self.n_qubits, 3)
        
        # Training loop
        optimizer = qml.AdamOptimizer(learning_rate)
        
        for epoch in range(epochs):
            # Compute cost and gradients
            cost, grads = qml.grad(self.cost_function, argnum=0)(self.model_params, X, labels)
            
            # Update parameters
            self.model_params = optimizer.apply(grads, self.model_params)
            
            # Log progress
            if epoch % 10 == 0:
                accuracy = self.evaluate_accuracy(X, labels)
                self.training_history.append({
                    'epoch': epoch,
                    'cost': cost,
                    'accuracy': accuracy
                })
                logger.info(f"Epoch {epoch}: Cost = {cost:.4f}, Accuracy = {accuracy:.4f}")
        
        # Final evaluation
        final_accuracy = self.evaluate_accuracy(X, labels)
        logger.info(f"Training completed. Final accuracy: {final_accuracy:.4f}")
        
        return {
            'final_accuracy': final_accuracy,
            'training_history': self.training_history,
            'model_params': self.model_params.tolist()
        }
    
    def evaluate_accuracy(self, X: np.ndarray, y: np.ndarray) -> float:
        """
        Evaluate model accuracy
        """
        predictions = []
        for x in X:
            pred = self.qnode(x, self.model_params)
            predictions.append(np.mean(pred))
        
        predictions = np.array(predictions)
        predictions = (predictions > self.anomaly_threshold).astype(int)
        
        return accuracy_score(y, predictions)
    
    def detect_anomaly(self, behavioral_data: pd.DataFrame) -> Dict:
        """
        Detect anomalies in behavioral data
        """
        if self.model_params is None:
            raise ValueError("Model must be trained before anomaly detection")
        
        # Preprocess data
        X = self.preprocess_behavioral_data(behavioral_data)
        
        anomalies = []
        risk_scores = []
        
        for i, x in enumerate(X):
            # Get quantum prediction
            pred = self.qnode(x, self.model_params)
            risk_score = np.mean(pred)
            
            # Determine if anomaly
            is_anomaly = risk_score > self.anomaly_threshold
            
            anomalies.append(is_anomaly)
            risk_scores.append(risk_score)
        
        # Generate detailed report
        report = {
            'timestamp': datetime.now().isoformat(),
            'total_samples': len(behavioral_data),
            'anomalies_detected': sum(anomalies),
            'anomaly_rate': sum(anomalies) / len(anomalies) if anomalies else 0,
            'average_risk_score': np.mean(risk_scores),
            'max_risk_score': np.max(risk_scores),
            'min_risk_score': np.min(risk_scores),
            'detailed_results': []
        }
        
        for i, (is_anomaly, risk_score) in enumerate(zip(anomalies, risk_scores)):
            sample_data = behavioral_data.iloc[i].to_dict()
            report['detailed_results'].append({
                'sample_id': i,
                'is_anomaly': bool(is_anomaly),
                'risk_score': float(risk_score),
                'behavioral_features': sample_data,
                'anomaly_type': self._classify_anomaly_type(sample_data, risk_score)
            })
        
        return report
    
    def _classify_anomaly_type(self, behavioral_data: Dict, risk_score: float) -> str:
        """
        Classify the type of anomaly based on behavioral patterns
        """
        if risk_score > 0.9:
            return "HIGH_RISK_SUSPICIOUS_ACTIVITY"
        elif risk_score > 0.8:
            return "MEDIUM_RISK_UNUSUAL_PATTERN"
        elif risk_score > 0.7:
            return "LOW_RISK_DEVIATION"
        else:
            return "NORMAL_ACTIVITY"
    
    def save_model(self, filepath: str):
        """
        Save the trained model
        """
        model_data = {
            'model_params': self.model_params.tolist(),
            'scaler_params': {
                'mean_': self.scaler.mean_.tolist(),
                'scale_': self.scaler.scale_.tolist()
            },
            'n_qubits': self.n_qubits,
            'n_layers': self.n_layers,
            'n_features': self.n_features,
            'anomaly_threshold': self.anomaly_threshold,
            'training_history': self.training_history
        }
        
        with open(filepath, 'w') as f:
            json.dump(model_data, f, indent=2)
        
        logger.info(f"Model saved to {filepath}")
    
    def load_model(self, filepath: str):
        """
        Load a trained model
        """
        with open(filepath, 'r') as f:
            model_data = json.load(f)
        
        self.model_params = np.array(model_data['model_params'])
        self.scaler.mean_ = np.array(model_data['scaler_params']['mean_'])
        self.scaler.scale_ = np.array(model_data['scaler_params']['scale_'])
        self.n_qubits = model_data['n_qubits']
        self.n_layers = model_data['n_layers']
        self.n_features = model_data['n_features']
        self.anomaly_threshold = model_data['anomaly_threshold']
        self.training_history = model_data['training_history']
        
        logger.info(f"Model loaded from {filepath}")


# Example usage and testing
if __name__ == "__main__":
    # Create sample behavioral data
    np.random.seed(42)
    n_samples = 100
    
    # Generate realistic behavioral data
    data = pd.DataFrame({
        'keystroke_timing_mean': np.random.normal(200, 50, n_samples),
        'keystroke_timing_std': np.random.normal(30, 10, n_samples),
        'login_time_pattern': np.random.uniform(0, 24, n_samples),
        'file_access_frequency': np.random.poisson(5, n_samples),
        'session_duration': np.random.exponential(1800, n_samples),
        'typing_speed': np.random.normal(60, 15, n_samples),
        'mouse_movement_pattern': np.random.normal(100, 25, n_samples),
        'page_visit_sequence': np.random.randint(1, 10, n_samples)
    })
    
    # Create labels (0 = normal, 1 = anomaly)
    labels = np.random.binomial(1, 0.1, n_samples)  # 10% anomalies
    
    # Initialize and train detector
    detector = QuantumAnomalyDetector(n_qubits=4, n_layers=3)
    
    # Train the model
    training_result = detector.train(data, labels, epochs=50)
    print(f"Training completed with accuracy: {training_result['final_accuracy']:.4f}")
    
    # Test anomaly detection
    test_data = data.iloc[:10]  # Test on first 10 samples
    anomaly_report = detector.detect_anomaly(test_data)
    
    print("\nAnomaly Detection Report:")
    print(f"Total samples: {anomaly_report['total_samples']}")
    print(f"Anomalies detected: {anomaly_report['anomalies_detected']}")
    print(f"Anomaly rate: {anomaly_report['anomaly_rate']:.2%}")
    print(f"Average risk score: {anomaly_report['average_risk_score']:.4f}")
    
    # Save model
    detector.save_model("quantum_anomaly_detector_model.json") 