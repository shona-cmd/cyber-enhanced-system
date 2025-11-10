"""
Anomaly detection module for NaashonSecureIoT.

Implements ML/DL models for real-time anomaly detection in IoT data streams.
Based on the proposal's AnomalyDetector model for edge computing.
"""

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    import numpy as np
    from typing import List, Dict, Any, Tuple, Literal
    import logging
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False
    import logging
    from typing import List, Dict, Any
    logger = logging.getLogger(__name__)
    logger.warning("PyTorch not available. Using mock anomaly detector.")

logger = logging.getLogger(__name__)
if not logger.handlers:
    handler = logging.StreamHandler()
    formatter = logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s")
    handler.setFormatter(formatter)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)


if TORCH_AVAILABLE:
    class AnomalyDetector(nn.Module):
        """
        Neural network for IoT anomaly detection.

        Lightweight DNN model suitable for edge devices.
        """

        def __init__(self, input_size: int = 10, hidden1: int = 64, hidden2: int = 32,
                     model_type: Literal["DNN", "RNN"] = "DNN"):
            """
            Initialize the anomaly detection model.

            Args:
                input_size: Number of input features
                hidden1: Size of first hidden layer
                hidden2: Size of second hidden layer
                model_type: Type of model ("DNN" or "RNN")
            """
            super().__init__()
            self.model_type = model_type

            if model_type == "DNN":
                self.fc1 = nn.Linear(input_size, hidden1)
                self.fc2 = nn.Linear(hidden1, hidden2)
                self.fc3 = nn.Linear(hidden2, 1)
                self.dropout = nn.Dropout(0.2)
            elif model_type == "RNN":
                self.rnn = nn.LSTM(input_size, hidden1, batch_first=True)
                self.fc1 = nn.Linear(hidden1, hidden2)
                self.fc2 = nn.Linear(hidden2, 1)
            else:
                raise ValueError(f"Invalid model_type: {model_type}")

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            """
            Forward pass through the network.

            Args:
                x: Input tensor

            Returns:
                Anomaly score (sigmoid output)
            """
            if self.model_type == "DNN":
                x = torch.relu(self.fc1(x))
                x = self.dropout(x)
                x = torch.relu(self.fc2(x))
                x = self.dropout(x)
                return torch.sigmoid(self.fc3(x))
            elif self.model_type == "RNN":
                # Assuming input is (batch_size, seq_len, input_size)
                _, (h_n, _) = self.rnn(x)
                x = torch.relu(self.fc1(h_n[-1]))  # Use last hidden state
                return torch.sigmoid(self.fc2(x))


class IoTAnomalyDetector:
    """
    Wrapper class for anomaly detection in IoT environments.

    Handles model training, inference, and integration with the framework.
    """

    def __init__(self, model_path: str = None, threshold: float = 0.85, model_type: str = "DNN"):
        """
        Initialize the anomaly detector.

        Args:
            model_path: Path to pre-trained model
            threshold: Anomaly detection threshold
            model_type: Type of model ("DNN" or "RNN")
        """
        if TORCH_AVAILABLE:
            self.model = AnomalyDetector(model_type=model_type)
            self.threshold = threshold
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self.model.to(self.device)

            if model_path:
                try:
                    self.load_model(model_path)
                except Exception as e:
                    logger.warning(f"Could not load model from {model_path}: {e}")

            self.model.eval()  # Set to evaluation mode
        else:
            self.threshold = threshold
            logger.warning("PyTorch not available. Using simple rule-based anomaly detection.")

    def load_model(self, path: str):
        """Load pre-trained model weights."""
        if TORCH_AVAILABLE:
            self.model.load_state_dict(torch.load(path, map_location=self.device))
            logger.info(f"Model loaded from {path}")
        else:
            logger.warning("Cannot load model: PyTorch not available")

    def save_model(self, path: str):
        """Save model weights."""
        if TORCH_AVAILABLE:
            torch.save(self.model.state_dict(), path)
            logger.info(f"Model saved to {path}")
        else:
            logger.warning("Cannot save model: PyTorch not available")

    def preprocess_data(self, data: Dict[str, Any]):
        """
        Preprocess IoT data for model input.

        Args:
            data: Raw IoT data dictionary

        Returns:
            Preprocessed tensor or features list
        """
        if TORCH_AVAILABLE:
            # Extract relevant features (customize based on your IoT data)
            features = []

            # Example features from CICIDS2017/ToN-IoT datasets
            features.append(data.get('packet_size', 0))
            features.append(data.get('flow_duration', 0))
            features.append(data.get('total_packets', 0))
            features.append(data.get('bytes_per_second', 0))
            features.append(data.get('protocol_type', 0))
            features.append(data.get('source_port', 0))
            features.append(data.get('destination_port', 0))
            features.append(data.get('flags', 0))
            features.append(data.get('ttl', 0))
            features.append(data.get('window_size', 0))

            # Ensure we have exactly 10 features
            while len(features) < 10:
                features.append(0)

            features_tensor = torch.tensor(features[:10], dtype=torch.float32).to(self.device)
            if self.model.model_type == "DNN":
                return features_tensor.unsqueeze(0)
            elif self.model.model_type == "RNN":
                return features_tensor.unsqueeze(0).unsqueeze(0)  # Add sequence length dimension
            else:
                raise ValueError(f"Invalid model_type: {self.model.model_type}")
        else:
            # Return features list for rule-based detection
            return [
                data.get('packet_size', 0),
                data.get('flow_duration', 0),
                data.get('total_packets', 0),
                data.get('bytes_per_second', 0),
                data.get('protocol_type', 0),
                data.get('source_port', 0),
                data.get('destination_port', 0),
                data.get('flags', 0),
                data.get('ttl', 0),
                data.get('window_size', 0)
            ]

    def detect_anomaly(self, data: Dict[str, Any]) -> float:
        """
        Detect anomalies in IoT data.

        Args:
            data: IoT data payload

        Returns:
            Anomaly score (0-1, higher = more anomalous)
        """
        if TORCH_AVAILABLE:
            try:
                input_tensor = self.preprocess_data(data)
                with torch.no_grad():
                    output = self.model(input_tensor)
                    score = output.item()
                return score
            except Exception as e:
                logger.error(f"Error in anomaly detection: {e}")
                return 0.0  # Assume normal if error
        else:
            # Simple rule-based anomaly detection
            features = self.preprocess_data(data)
            score = 0.0

            # Simple rules for anomaly detection
            if features[0] > 5000:  # packet_size > 5000
                score += 0.3
            if features[3] > 500000:  # bytes_per_second > 500k
                score += 0.4
            if features[2] > 1000:  # total_packets > 1000
                score += 0.3

            return min(score, 1.0)  # Cap at 1.0

    def train_model(self, train_data: List[Dict[str, Any]], labels: List[int],
                   epochs: int = 10, lr: float = 0.001):
        """
        Train the anomaly detection model.

        Args:
            train_data: List of training data dictionaries
            labels: Binary labels (0=normal, 1=anomaly)
            epochs: Number of training epochs
            lr: Learning rate
        """
        if TORCH_AVAILABLE:
            self.model.train()
            optimizer = torch.optim.Adam(self.model.parameters(), lr=lr)
            criterion = nn.BCELoss()

            for epoch in range(epochs):
                total_loss = 0
                for i, data in enumerate(train_data):
                    input_tensor = self.preprocess_data(data)
                    if self.model.model_type == "RNN":
                        label = torch.tensor([labels[i]], dtype=torch.float32).unsqueeze(0).to(self.device)
                    else:
                        label = torch.tensor([labels[i]], dtype=torch.float32).to(self.device)

                    optimizer.zero_grad()
                    output = self.model(input_tensor)
                    loss = criterion(output, label)
                    loss.backward()
                    optimizer.step()

                    total_loss += loss.item()

                logger.info(f"Epoch {epoch+1}/{epochs}, Loss: {total_loss/len(train_data):.4f}")

            self.model.eval()
        else:
            logger.warning("Cannot train model: PyTorch not available")

    def get_active_threats(self) -> int:
        """Get count of active threats (placeholder for now)."""
        logger.info("Getting active threat count...")
        # In a real implementation, this would track recent anomalies
        return 0
