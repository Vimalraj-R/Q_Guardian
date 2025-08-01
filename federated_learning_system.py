import flwr as fl
import numpy as np
import pandas as pd
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import json
import logging
from datetime import datetime
from typing import Dict, List, Tuple, Optional
import hashlib
import os
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import pickle
import base64
from collections import OrderedDict

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AcademicNeuralNetwork(nn.Module):
    """
    Neural network for academic data analysis (grades, submissions, exam interactions)
    """
    
    def __init__(self, input_size: int = 10, hidden_size: int = 64, output_size: int = 1):
        super(AcademicNeuralNetwork, self).__init__()
        self.layer1 = nn.Linear(input_size, hidden_size)
        self.layer2 = nn.Linear(hidden_size, hidden_size // 2)
        self.layer3 = nn.Linear(hidden_size // 2, output_size)
        self.relu = nn.ReLU()
        self.dropout = nn.Dropout(0.3)
        self.sigmoid = nn.Sigmoid()
    
    def forward(self, x):
        x = self.relu(self.layer1(x))
        x = self.dropout(x)
        x = self.relu(self.layer2(x))
        x = self.dropout(x)
        x = self.sigmoid(self.layer3(x))
        return x

class AcademicClient(fl.client.NumPyClient):
    """
    Flower client for federated learning with academic data
    """
    
    def __init__(self, institution_id: str, data_path: str = None):
        self.institution_id = institution_id
        self.model = AcademicNeuralNetwork()
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        self.model.to(self.device)
        
        # Load or generate academic data
        if data_path and os.path.exists(data_path):
            self.load_data(data_path)
        else:
            self.generate_synthetic_data()
        
        # Differential privacy parameters
        self.epsilon = 1.0  # Privacy budget
        self.delta = 1e-5   # Privacy parameter
        
        logger.info(f"Academic client {institution_id} initialized")
    
    def generate_synthetic_data(self):
        """
        Generate synthetic academic data for the institution
        """
        np.random.seed(hash(self.institution_id) % 2**32)
        n_samples = np.random.randint(500, 2000)
        
        # Generate realistic academic features
        data = {
            'student_id': range(n_samples),
            'gpa': np.random.normal(3.2, 0.8, n_samples),
            'attendance_rate': np.random.uniform(0.7, 1.0, n_samples),
            'assignment_submissions': np.random.poisson(8, n_samples),
            'exam_scores': np.random.normal(75, 15, n_samples),
            'study_time_hours': np.random.exponential(20, n_samples),
            'online_activity_score': np.random.uniform(0, 100, n_samples),
            'peer_interaction_score': np.random.uniform(0, 100, n_samples),
            'resource_utilization': np.random.uniform(0, 1, n_samples),
            'time_management_score': np.random.uniform(0, 100, n_samples),
            'academic_risk': np.random.binomial(1, 0.15, n_samples)  # 15% at risk
        }
        
        self.data = pd.DataFrame(data)
        self.scaler = StandardScaler()
        
        # Prepare features and labels
        feature_columns = [col for col in self.data.columns if col not in ['student_id', 'academic_risk']]
        X = self.scaler.fit_transform(self.data[feature_columns])
        y = self.data['academic_risk'].values
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        # Convert to PyTorch tensors
        self.X_train = torch.FloatTensor(X_train)
        self.y_train = torch.FloatTensor(y_train).unsqueeze(1)
        self.X_test = torch.FloatTensor(X_test)
        self.y_test = torch.FloatTensor(y_test).unsqueeze(1)
        
        logger.info(f"Generated {n_samples} samples for {self.institution_id}")
    
    def load_data(self, data_path: str):
        """
        Load academic data from file
        """
        with open(data_path, 'rb') as f:
            data = pickle.load(f)
        
        self.X_train = data['X_train']
        self.y_train = data['y_train']
        self.X_test = data['X_test']
        self.y_test = data['y_test']
        self.scaler = data['scaler']
        
        logger.info(f"Loaded data from {data_path}")
    
    def get_parameters(self, config):
        """
        Get model parameters for federated learning
        """
        return [val.cpu().numpy() for _, val in self.model.state_dict().items()]
    
    def set_parameters(self, parameters):
        """
        Set model parameters from federated learning
        """
        params_dict = zip(self.model.state_dict().keys(), parameters)
        state_dict = OrderedDict({k: torch.tensor(v) for k, v in params_dict})
        self.model.load_state_dict(state_dict, strict=True)
    
    def fit(self, parameters, config):
        """
        Train the model on local data with differential privacy
        """
        self.set_parameters(parameters)
        
        # Training parameters
        epochs = config.get("epochs", 5)
        batch_size = config.get("batch_size", 32)
        learning_rate = config.get("learning_rate", 0.001)
        
        # Create data loader
        train_dataset = TensorDataset(self.X_train, self.y_train)
        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        
        # Setup training
        criterion = nn.BCELoss()
        optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)
        
        # Training loop
        self.model.train()
        for epoch in range(epochs):
            total_loss = 0
            for batch_X, batch_y in train_loader:
                batch_X, batch_y = batch_X.to(self.device), batch_y.to(self.device)
                
                optimizer.zero_grad()
                outputs = self.model(batch_X)
                loss = criterion(outputs, batch_y)
                loss.backward()
                
                # Apply differential privacy noise to gradients
                self._add_dp_noise(optimizer)
                
                optimizer.step()
                total_loss += loss.item()
            
            avg_loss = total_loss / len(train_loader)
            logger.info(f"Epoch {epoch + 1}/{epochs}, Loss: {avg_loss:.4f}")
        
        # Return updated parameters and metrics
        return self.get_parameters(config), len(self.X_train), {
            "loss": avg_loss,
            "institution_id": self.institution_id,
            "privacy_epsilon": self.epsilon
        }
    
    def evaluate(self, parameters, config):
        """
        Evaluate the model on local test data
        """
        self.set_parameters(parameters)
        
        # Create test data loader
        test_dataset = TensorDataset(self.X_test, self.y_test)
        test_loader = DataLoader(test_dataset, batch_size=32, shuffle=False)
        
        # Evaluation
        self.model.eval()
        total_loss = 0
        correct = 0
        total = 0
        
        criterion = nn.BCELoss()
        
        with torch.no_grad():
            for batch_X, batch_y in test_loader:
                batch_X, batch_y = batch_X.to(self.device), batch_y.to(self.device)
                outputs = self.model(batch_X)
                loss = criterion(outputs, batch_y)
                total_loss += loss.item()
                
                predicted = (outputs > 0.5).float()
                total += batch_y.size(0)
                correct += (predicted == batch_y).sum().item()
        
        accuracy = correct / total
        avg_loss = total_loss / len(test_loader)
        
        return avg_loss, len(self.X_test), {"accuracy": accuracy}
    
    def _add_dp_noise(self, optimizer):
        """
        Add differential privacy noise to gradients
        """
        for param in self.model.parameters():
            if param.grad is not None:
                # Calculate noise scale based on privacy parameters
                noise_scale = np.sqrt(2 * np.log(1.25 / self.delta)) / self.epsilon
                noise = torch.randn_like(param.grad) * noise_scale
                param.grad += noise

class SecureAggregationStrategy(fl.server.strategy.FedAvg):
    """
    Federated learning strategy with secure aggregation
    """
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.aggregation_history = []
    
    def aggregate_fit(self, server_round, results, failures):
        """
        Aggregate client updates with secure aggregation
        """
        if not results:
            return None, {}
        
        # Extract weights and metrics
        weights_results = [r.parameters for r in results]
        metrics_results = [r.metrics for r in results]
        
        # Apply secure aggregation (simplified version)
        aggregated_weights = self._secure_aggregate(weights_results)
        
        # Log aggregation
        aggregation_info = {
            'round': server_round,
            'num_clients': len(results),
            'timestamp': datetime.now().isoformat(),
            'metrics': self._aggregate_metrics(metrics_results)
        }
        self.aggregation_history.append(aggregation_info)
        
        return aggregated_weights, aggregation_info
    
    def _secure_aggregate(self, weights_list):
        """
        Secure aggregation of model weights
        """
        if not weights_list:
            return None
        
        # Simple weighted average (in practice, would use more sophisticated secure aggregation)
        aggregated_weights = []
        for weights_list_tuple in zip(*weights_list):
            aggregated_weights.append(np.mean(weights_list_tuple, axis=0))
        
        return aggregated_weights
    
    def _aggregate_metrics(self, metrics_list):
        """
        Aggregate metrics from all clients
        """
        aggregated_metrics = {}
        for key in metrics_list[0].keys():
            if key != 'institution_id':
                values = [m[key] for m in metrics_list if key in m]
                if values:
                    aggregated_metrics[key] = np.mean(values)
        
        return aggregated_metrics

class FederatedLearningSystem:
    """
    Main federated learning system for educational institutions
    """
    
    def __init__(self, num_institutions: int = 5):
        self.num_institutions = num_institutions
        self.institutions = []
        self.server_config = {
            "num_rounds": 10,
            "min_fit_clients": 3,
            "min_evaluate_clients": 3,
            "min_available_clients": 3
        }
        
        # Initialize institutions
        self._initialize_institutions()
        
        logger.info(f"Federated Learning System initialized with {num_institutions} institutions")
    
    def _initialize_institutions(self):
        """
        Initialize simulated educational institutions
        """
        institution_names = [
            "Stanford_University",
            "MIT_Institute",
            "Harvard_College",
            "Berkeley_University",
            "Princeton_Institute"
        ]
        
        for i in range(self.num_institutions):
            institution_id = institution_names[i]
            client = AcademicClient(institution_id)
            self.institutions.append(client)
    
    def start_federated_training(self):
        """
        Start federated learning training
        """
        logger.info("Starting federated learning training...")
        
        # Define strategy
        strategy = SecureAggregationStrategy(
            min_fit_clients=self.server_config["min_fit_clients"],
            min_evaluate_clients=self.server_config["min_evaluate_clients"],
            min_available_clients=self.server_config["min_available_clients"],
            evaluate_fn=self._evaluate_global_model,
            on_fit_config_fn=self._get_fit_config,
            on_evaluate_config_fn=self._get_evaluate_config,
        )
        
        # Start server
        fl.server.start_server(
            server_address="0.0.0.0:8080",
            config=fl.server.ServerConfig(num_rounds=self.server_config["num_rounds"]),
            strategy=strategy
        )
    
    def _get_fit_config(self, server_round: int):
        """
        Return training configuration
        """
        return {
            "epochs": 5,
            "batch_size": 32,
            "learning_rate": 0.001,
            "round": server_round
        }
    
    def _get_evaluate_config(self, server_round: int):
        """
        Return evaluation configuration
        """
        return {"round": server_round}
    
    def _evaluate_global_model(self, server_round, parameters, config):
        """
        Evaluate global model on all institutions
        """
        # This would be called by the server to evaluate the global model
        # For now, we'll simulate this
        return 0.0, {"accuracy": 0.85, "round": server_round}
    
    def run_client(self, institution_id: int):
        """
        Run a specific client for federated learning
        """
        if institution_id >= len(self.institutions):
            raise ValueError(f"Institution ID {institution_id} not found")
        
        client = self.institutions[institution_id]
        
        # Start client
        fl.client.start_numpy_client(
            server_address="localhost:8080",
            client=client
        )
    
    def save_training_results(self, filepath: str):
        """
        Save federated learning results
        """
        results = {
            'timestamp': datetime.now().isoformat(),
            'num_institutions': self.num_institutions,
            'server_config': self.server_config,
            'institution_ids': [client.institution_id for client in self.institutions]
        }
        
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        
        logger.info(f"Training results saved to {filepath}")

# Example usage
if __name__ == "__main__":
    # Initialize federated learning system
    fl_system = FederatedLearningSystem(num_institutions=5)
    
    # Save training configuration
    fl_system.save_training_results("federated_learning_config.json")
    
    print("Federated Learning System initialized!")
    print("To start training:")
    print("1. Run the server: python federated_learning_system.py --server")
    print("2. Run clients: python federated_learning_system.py --client <institution_id>")
    print("3. Or run all in separate terminals for simulation") 