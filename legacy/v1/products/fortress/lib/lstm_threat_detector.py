#!/usr/bin/env python3
"""
Fortress LSTM Threat Detection Module

Uses LSTM neural networks to detect attack patterns and predict threats.
Focus: HOW users are targeted (attack sequences), NOT what they browse.

Features:
- Trains on attack sequences (not browsing data)
- Predicts next attack type in a sequence
- Anomaly detection for unusual attack patterns
- Daily automatic retraining

Author: HookProbe Team
Version: 5.0.0
License: AGPL-3.0
"""

import json
import os
import pickle
from pathlib import Path
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict
import numpy as np

# Try to import ML libraries (optional for base install)
try:
    import torch
    import torch.nn as nn
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

try:
    from sklearn.preprocessing import LabelEncoder, StandardScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


# Attack category encoding
ATTACK_CATEGORIES = [
    "unknown",
    "port_scan",
    "address_scan",
    "syn_flood",
    "udp_flood",
    "icmp_flood",
    "brute_force",
    "sql_injection",
    "xss",
    "dns_tunneling",
    "malware_c2",
    "data_exfiltration",
    "privilege_escalation",
    "lateral_movement",
    "dos_attack",
    "reconnaissance"
]

# Data directories
ML_DATA_DIR = Path("/opt/hookprobe/fortress/data/ml-models")
TRAINING_DIR = Path("/opt/hookprobe/fortress/data/threat-intel")
MODEL_DIR = Path("/opt/hookprobe/fortress/data/ml-models/trained")


class AttackSequenceEncoder:
    """Encodes attack sequences for LSTM input"""

    def __init__(self):
        self.category_to_idx = {cat: idx for idx, cat in enumerate(ATTACK_CATEGORIES)}
        self.idx_to_category = {idx: cat for idx, cat in enumerate(ATTACK_CATEGORIES)}
        self.num_categories = len(ATTACK_CATEGORIES)

    def encode_category(self, category: str) -> int:
        """Encode attack category to integer"""
        cat_lower = category.lower().replace(" ", "_").replace("-", "_")
        return self.category_to_idx.get(cat_lower, 0)  # 0 = unknown

    def decode_category(self, idx: int) -> str:
        """Decode integer to attack category"""
        return self.idx_to_category.get(idx, "unknown")

    def encode_sequence(self, categories: List[str], max_len: int = 20) -> np.ndarray:
        """Encode a sequence of attack categories"""
        encoded = [self.encode_category(cat) for cat in categories[:max_len]]
        # Pad sequence
        while len(encoded) < max_len:
            encoded.append(0)
        return np.array(encoded)

    def encode_features(self, sequence: Dict[str, Any]) -> np.ndarray:
        """Encode full sequence features"""
        features = []

        # Category sequence
        categories = sequence.get("categories", [])
        cat_encoded = self.encode_sequence(categories)
        features.extend(cat_encoded)

        # Severity pattern
        severities = sequence.get("severity_pattern", [])
        sev_padded = severities[:20] + [0] * (20 - len(severities))
        features.extend(sev_padded[:20])

        # Port pattern (normalized)
        ports = sequence.get("port_pattern", [])
        ports_normalized = [min(p / 65535.0, 1.0) for p in ports[:20]]
        ports_padded = ports_normalized + [0] * (20 - len(ports_normalized))
        features.extend(ports_padded[:20])

        # Event count (normalized)
        event_count = min(sequence.get("event_count", 0) / 100.0, 1.0)
        features.append(event_count)

        return np.array(features, dtype=np.float32)


if TORCH_AVAILABLE:
    class ThreatLSTM(nn.Module):
        """LSTM model for threat pattern detection"""

        def __init__(self, input_size: int = 61, hidden_size: int = 64,
                     num_layers: int = 2, num_classes: int = 16):
            super(ThreatLSTM, self).__init__()

            self.hidden_size = hidden_size
            self.num_layers = num_layers

            self.lstm = nn.LSTM(
                input_size=input_size,
                hidden_size=hidden_size,
                num_layers=num_layers,
                batch_first=True,
                dropout=0.2 if num_layers > 1 else 0
            )

            self.fc = nn.Sequential(
                nn.Linear(hidden_size, 32),
                nn.ReLU(),
                nn.Dropout(0.3),
                nn.Linear(32, num_classes)
            )

        def forward(self, x: torch.Tensor) -> torch.Tensor:
            # x shape: (batch, seq_len, features)
            # Reshape if needed
            if x.dim() == 2:
                x = x.unsqueeze(1)

            h0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size).to(x.device)
            c0 = torch.zeros(self.num_layers, x.size(0), self.hidden_size).to(x.device)

            out, _ = self.lstm(x, (h0, c0))
            out = out[:, -1, :]  # Take last output
            out = self.fc(out)
            return out


class LSTMThreatDetector:
    """
    LSTM-based threat detection for Fortress

    Analyzes attack sequences to:
    1. Predict next attack type
    2. Detect anomalous patterns
    3. Calculate threat score contribution
    """

    def __init__(self, model_path: Optional[Path] = None):
        self.encoder = AttackSequenceEncoder()
        self.model = None
        self.model_path = model_path or MODEL_DIR / "threat_lstm.pt"
        self.training_history = []

        MODEL_DIR.mkdir(parents=True, exist_ok=True)

        if TORCH_AVAILABLE:
            self._load_model()
        else:
            print("Warning: PyTorch not available. LSTM detection disabled.")

    def _load_model(self) -> bool:
        """Load trained model if available"""
        if not TORCH_AVAILABLE:
            return False

        try:
            if self.model_path.exists():
                self.model = ThreatLSTM()
                self.model.load_state_dict(torch.load(self.model_path))
                self.model.eval()
                print(f"Loaded model from {self.model_path}")
                return True
        except Exception as e:
            print(f"Could not load model: {e}")

        # Initialize new model
        self.model = ThreatLSTM()
        return False

    def load_training_data(self, days: int = 7) -> List[Dict]:
        """Load training data from last N days"""
        sequences = []
        cutoff = datetime.now() - timedelta(days=days)

        for training_file in ML_DATA_DIR.glob("training_*.jsonl"):
            try:
                # Parse date from filename
                date_str = training_file.stem.split("_")[1]
                file_date = datetime.strptime(date_str, "%Y%m%d")

                if file_date >= cutoff:
                    with open(training_file, 'r') as f:
                        for line in f:
                            try:
                                seq = json.loads(line.strip())
                                if seq.get("categories"):
                                    sequences.append(seq)
                            except json.JSONDecodeError:
                                continue
            except (ValueError, IndexError):
                continue

        print(f"Loaded {len(sequences)} training sequences from last {days} days")
        return sequences

    def prepare_training_data(self, sequences: List[Dict]) -> Tuple[np.ndarray, np.ndarray]:
        """Prepare sequences for training"""
        X = []
        y = []

        for seq in sequences:
            categories = seq.get("categories", [])
            if len(categories) < 2:
                continue

            # Input: features of the sequence
            features = self.encoder.encode_features(seq)
            X.append(features)

            # Target: most common category in sequence (simplified)
            # In real scenario, predict next category
            target_cat = categories[-1] if categories else "unknown"
            y.append(self.encoder.encode_category(target_cat))

        return np.array(X), np.array(y)

    def train(self, epochs: int = 50, batch_size: int = 32) -> Dict[str, Any]:
        """Train the LSTM model on collected data"""
        if not TORCH_AVAILABLE:
            return {"status": "error", "message": "PyTorch not available"}

        sequences = self.load_training_data()
        if len(sequences) < 10:
            return {
                "status": "skipped",
                "message": f"Insufficient data: {len(sequences)} sequences (need 10+)"
            }

        X, y = self.prepare_training_data(sequences)
        if len(X) < 10:
            return {
                "status": "skipped",
                "message": f"Insufficient valid sequences: {len(X)}"
            }

        # Convert to tensors
        X_tensor = torch.FloatTensor(X)
        y_tensor = torch.LongTensor(y)

        # Simple training loop
        self.model = ThreatLSTM(input_size=X.shape[1])
        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.001)
        criterion = nn.CrossEntropyLoss()

        self.model.train()
        losses = []

        for epoch in range(epochs):
            # Shuffle data
            perm = torch.randperm(len(X_tensor))
            X_shuffled = X_tensor[perm]
            y_shuffled = y_tensor[perm]

            epoch_loss = 0
            num_batches = 0

            for i in range(0, len(X_shuffled), batch_size):
                batch_X = X_shuffled[i:i+batch_size]
                batch_y = y_shuffled[i:i+batch_size]

                optimizer.zero_grad()
                outputs = self.model(batch_X)
                loss = criterion(outputs, batch_y)
                loss.backward()
                optimizer.step()

                epoch_loss += loss.item()
                num_batches += 1

            avg_loss = epoch_loss / max(num_batches, 1)
            losses.append(avg_loss)

            if (epoch + 1) % 10 == 0:
                print(f"Epoch {epoch+1}/{epochs}, Loss: {avg_loss:.4f}")

        # Save model
        torch.save(self.model.state_dict(), self.model_path)

        # Calculate accuracy on training set
        self.model.eval()
        with torch.no_grad():
            outputs = self.model(X_tensor)
            _, predicted = torch.max(outputs.data, 1)
            accuracy = (predicted == y_tensor).sum().item() / len(y_tensor)

        result = {
            "status": "success",
            "timestamp": datetime.now().isoformat(),
            "sequences_trained": len(X),
            "epochs": epochs,
            "final_loss": losses[-1] if losses else 0,
            "accuracy": accuracy,
            "model_path": str(self.model_path)
        }

        # Save training history
        self.training_history.append(result)
        history_file = MODEL_DIR / "training_history.json"
        try:
            history = []
            if history_file.exists():
                with open(history_file, 'r') as f:
                    history = json.load(f)
            history.append(result)
            with open(history_file, 'w') as f:
                json.dump(history[-100:], f, indent=2)  # Keep last 100
        except Exception:
            pass

        return result

    def predict(self, sequence: Dict[str, Any]) -> Dict[str, Any]:
        """Predict threat score and next likely attack"""
        result = {
            "threat_score": 0.0,
            "predicted_attack": "unknown",
            "confidence": 0.0,
            "anomaly_score": 0.0
        }

        if not TORCH_AVAILABLE or self.model is None:
            return result

        try:
            # Encode features
            features = self.encoder.encode_features(sequence)
            X = torch.FloatTensor(features).unsqueeze(0)

            # Get prediction
            self.model.eval()
            with torch.no_grad():
                outputs = self.model(X)
                probs = torch.softmax(outputs, dim=1)
                confidence, predicted = torch.max(probs, 1)

                predicted_cat = self.encoder.decode_category(predicted.item())

            result["predicted_attack"] = predicted_cat
            result["confidence"] = confidence.item()

            # Calculate threat score based on prediction
            # Higher for more severe predicted attacks
            severe_attacks = ["malware_c2", "data_exfiltration", "sql_injection",
                           "privilege_escalation", "lateral_movement"]
            if predicted_cat in severe_attacks:
                result["threat_score"] = 0.7 + (confidence.item() * 0.3)
            elif predicted_cat in ["port_scan", "address_scan", "reconnaissance"]:
                result["threat_score"] = 0.3 + (confidence.item() * 0.2)
            else:
                result["threat_score"] = 0.1 + (confidence.item() * 0.4)

            # Anomaly score: low confidence = anomaly
            result["anomaly_score"] = 1.0 - confidence.item()

        except Exception as e:
            print(f"Prediction error: {e}")

        return result

    def analyze_current_threats(self, aggregated_file: Path = None) -> Dict[str, Any]:
        """Analyze current threat patterns"""
        if aggregated_file is None:
            aggregated_file = TRAINING_DIR / "aggregated.json"

        result = {
            "timestamp": datetime.now().isoformat(),
            "lstm_enabled": TORCH_AVAILABLE and self.model is not None,
            "threat_score": 0.0,
            "predictions": [],
            "pattern_distribution": {}
        }

        try:
            if aggregated_file.exists():
                with open(aggregated_file, 'r') as f:
                    data = json.load(f)
                result["pattern_distribution"] = data.get("pattern_distribution", {})

            # Load recent sequences and predict
            sequences = self.load_training_data(days=1)
            if sequences and self.model is not None:
                for seq in sequences[-10:]:  # Last 10 sequences
                    pred = self.predict(seq)
                    result["predictions"].append(pred)

                # Average threat score
                if result["predictions"]:
                    result["threat_score"] = sum(
                        p["threat_score"] for p in result["predictions"]
                    ) / len(result["predictions"])

        except Exception as e:
            print(f"Analysis error: {e}")

        return result


def daily_training():
    """Run daily training - called by systemd timer"""
    print(f"[{datetime.now()}] Starting daily LSTM training...")

    detector = LSTMThreatDetector()
    result = detector.train(epochs=100)

    print(f"Training result: {result['status']}")
    if result["status"] == "success":
        print(f"  Sequences: {result['sequences_trained']}")
        print(f"  Accuracy: {result['accuracy']:.2%}")
        print(f"  Model saved: {result['model_path']}")


def main():
    """CLI interface for LSTM threat detector"""
    import argparse

    parser = argparse.ArgumentParser(description="Fortress LSTM Threat Detector")
    parser.add_argument("--train", action="store_true", help="Train model")
    parser.add_argument("--analyze", action="store_true", help="Analyze current threats")
    parser.add_argument("--status", action="store_true", help="Show model status")
    parser.add_argument("--epochs", type=int, default=50, help="Training epochs")

    args = parser.parse_args()

    detector = LSTMThreatDetector()

    if args.train:
        result = detector.train(epochs=args.epochs)
        print(json.dumps(result, indent=2))

    elif args.analyze:
        result = detector.analyze_current_threats()
        print(json.dumps(result, indent=2))

    elif args.status:
        status = {
            "torch_available": TORCH_AVAILABLE,
            "sklearn_available": SKLEARN_AVAILABLE,
            "model_loaded": detector.model is not None,
            "model_path": str(detector.model_path),
            "model_exists": detector.model_path.exists(),
            "training_data_dir": str(ML_DATA_DIR),
            "num_categories": len(ATTACK_CATEGORIES)
        }
        print(json.dumps(status, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
