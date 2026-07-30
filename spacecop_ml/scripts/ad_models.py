"""
Written by Dominic Berry in Feb 2026
Modified for Rust preprocessing integration

Python now ONLY trains the autoencoder - all preprocessing done in Rust
"""

import json
import os
import sys
import argparse
import numpy as np
from tensorflow.keras import Input, layers # type: ignore
from tensorflow.keras.models import Model # type: ignore
import tensorflow as tf
import tf2onnx

class AutoencoderForAnomalyDetection:
    def __init__(self, model_dir: str, debug=True):
        self.model_dir = model_dir
        self._debug = debug

        # Paths
        self.model_path = os.path.join(model_dir, "anomaly_detector.keras")
        self.onnx_model_path = os.path.join(model_dir, "anomaly_detector.onnx")
        self.metadata_path = os.path.join(model_dir, "metadata.json")
        self.preprocessing_metadata_path = os.path.join(model_dir, "preprocessing_metadata.json")

        # Model Training Config
        self.epochs = 50
        self.batch_size = 32
        self.shuffle = True
        self.model_training_verbosity = 1
        self.optimizer = 'adam'
        self.loss = 'mse'

    def debug(self, *message) -> None:
        if self._debug:
            print(*message)

    def determine_encoding_dim(self, input_dim: int) -> int:
        """
        Dynamically determine encoding dimension based on input size
        
        Rule of thumb: encoding dim should be roughly 10-20% of input dim
        but with reasonable bounds
        """
        if input_dim <= 4:
            return 2
        elif input_dim <= 10:
            return max(2, input_dim // 3)
        elif input_dim <= 20:
            return max(3, input_dim // 4)
        elif input_dim <= 50:
            return max(5, input_dim // 5)
        elif input_dim <= 100:
            return max(10, input_dim // 6)
        elif input_dim <= 200:
            return max(15, input_dim // 8)
        else:
            return max(20, input_dim // 10)

    def create_model(self, input_dim: int):
        """
        Create autoencoder with dynamic architecture based on input dimensions
        Architecture: input -> hidden layers -> bottleneck -> hidden layers -> output
        """
        input_layer = Input(shape=(input_dim,))
        
        # Determine encoding dimension dynamically
        encoding_dim = self.determine_encoding_dim(input_dim)
        
        self.debug(f"Creating autoencoder: {input_dim} -> ... -> {encoding_dim} -> ... -> {input_dim}")
        
        # Determine architecture based on input size
        if input_dim <= 8:
            # Very small: input -> hidden -> encoding -> hidden -> output
            hidden_dim = max(2, input_dim // 2)
            encoded = layers.Dense(hidden_dim, activation='relu')(input_layer)
            encoded = layers.Dense(encoding_dim, activation='relu')(encoded)
            decoded = layers.Dense(hidden_dim, activation='relu')(encoded)
            architecture = [input_dim, hidden_dim, encoding_dim, hidden_dim, input_dim]
            
        elif input_dim <= 32:
            # Small: input -> h1 -> h2 -> encoding -> h2 -> h1 -> output
            h1 = max(input_dim * 2 // 3, encoding_dim * 3)
            h2 = max(input_dim // 2, encoding_dim * 2)
            encoded = layers.Dense(h1, activation='relu')(input_layer)
            encoded = layers.Dense(h2, activation='relu')(encoded)
            encoded = layers.Dense(encoding_dim, activation='relu')(encoded)
            decoded = layers.Dense(h2, activation='relu')(encoded)
            decoded = layers.Dense(h1, activation='relu')(decoded)
            architecture = [input_dim, h1, h2, encoding_dim, h2, h1, input_dim]
            
        elif input_dim <= 64:
            # Medium: input -> h1 -> h2 -> h3 -> encoding -> h3 -> h2 -> h1 -> output
            h1 = max(48, encoding_dim * 4)
            h2 = max(32, encoding_dim * 3)
            h3 = max(16, encoding_dim * 2)
            encoded = layers.Dense(h1, activation='relu')(input_layer)
            encoded = layers.Dense(h2, activation='relu')(encoded)
            encoded = layers.Dense(h3, activation='relu')(encoded)
            encoded = layers.Dense(encoding_dim, activation='relu')(encoded)
            decoded = layers.Dense(h3, activation='relu')(encoded)
            decoded = layers.Dense(h2, activation='relu')(decoded)
            decoded = layers.Dense(h1, activation='relu')(decoded)
            architecture = [input_dim, h1, h2, h3, encoding_dim, h3, h2, h1, input_dim]
            
        elif input_dim <= 128:
            # Large: deeper network
            h1 = max(96, encoding_dim * 5)
            h2 = max(64, encoding_dim * 4)
            h3 = max(32, encoding_dim * 3)
            h4 = max(16, encoding_dim * 2)
            encoded = layers.Dense(h1, activation='relu')(input_layer)
            encoded = layers.Dense(h2, activation='relu')(encoded)
            encoded = layers.Dense(h3, activation='relu')(encoded)
            encoded = layers.Dense(h4, activation='relu')(encoded)
            encoded = layers.Dense(encoding_dim, activation='relu')(encoded)
            decoded = layers.Dense(h4, activation='relu')(encoded)
            decoded = layers.Dense(h3, activation='relu')(decoded)
            decoded = layers.Dense(h2, activation='relu')(decoded)
            decoded = layers.Dense(h1, activation='relu')(decoded)
            architecture = [input_dim, h1, h2, h3, h4, encoding_dim, h4, h3, h2, h1, input_dim]
            
        else:
            # Very large: even deeper
            h1 = max(128, encoding_dim * 6)
            h2 = max(96, encoding_dim * 5)
            h3 = max(64, encoding_dim * 4)
            h4 = max(32, encoding_dim * 3)
            h5 = max(16, encoding_dim * 2)
            encoded = layers.Dense(h1, activation='relu')(input_layer)
            encoded = layers.Dense(h2, activation='relu')(encoded)
            encoded = layers.Dense(h3, activation='relu')(encoded)
            encoded = layers.Dense(h4, activation='relu')(encoded)
            encoded = layers.Dense(h5, activation='relu')(encoded)
            encoded = layers.Dense(encoding_dim, activation='relu')(encoded)
            decoded = layers.Dense(h5, activation='relu')(encoded)
            decoded = layers.Dense(h4, activation='relu')(decoded)
            decoded = layers.Dense(h3, activation='relu')(decoded)
            decoded = layers.Dense(h2, activation='relu')(decoded)
            decoded = layers.Dense(h1, activation='relu')(decoded)
            architecture = [input_dim, h1, h2, h3, h4, h5, encoding_dim, h5, h4, h3, h2, h1, input_dim]
        
        decoded = layers.Dense(input_dim, activation='sigmoid')(decoded)

        autoencoder = Model(inputs=input_layer, outputs=decoded)
        autoencoder.compile(optimizer=self.optimizer, loss=self.loss)
        
        if self._debug:
            self.debug(f"Architecture: {' -> '.join(map(str, architecture))}")
            autoencoder.summary()

        return autoencoder, encoding_dim, architecture

    def export_to_onnx(self, model):
        """Export the Keras model to ONNX format for Rust compatibility"""
        spec = (tf.TensorSpec(model.input.shape, tf.float32, name="input"),)
        output_path = self.onnx_model_path
        
        model_proto, _ = tf2onnx.convert.from_keras(model, input_signature=spec, opset=13)
        with open(output_path, "wb") as f:
            f.write(model_proto.SerializeToString())
        
        self.debug(f"Model exported to ONNX format: {output_path}")

    def train(self):
        """
        Train autoencoder on PREPROCESSED data from Rust
        No preprocessing happens here - data is already scaled and ready
        """
        # Load preprocessed data from CSV (created by Rust)
        data_path = os.path.join(self.model_dir, "training_data.csv")
        if not os.path.exists(data_path):
            raise FileNotFoundError(f"Preprocessed data not found: {data_path}")
        
        # Check file size
        file_size = os.path.getsize(data_path)
        if file_size == 0:
            raise ValueError(f"Preprocessed data file is empty: {data_path}")
        
        self.debug(f"Loading data from {data_path} ({file_size} bytes)")
        
        try:
            X = np.loadtxt(data_path, delimiter=',', ndmin=2)  # ndmin=2 ensures 2D array
        except Exception as e:
            self.debug(f"Error loading data: {e}")
            # Try to read first few lines for debugging
            with open(data_path, 'r') as f:
                lines = f.readlines()[:5]
                self.debug(f"First few lines of file:\n{''.join(lines)}")
            raise
        
        self.debug(f"Loaded preprocessed data: {X.shape}")
        
        if X.shape[0] == 0:
            raise ValueError(f"No samples in training data: {data_path}")
        
        if X.shape[1] == 0:
            raise ValueError(f"No features in training data: {data_path}")
        
        # Load preprocessing metadata (for reference)
        if os.path.exists(self.preprocessing_metadata_path):
            with open(self.preprocessing_metadata_path, 'r') as f:
                preprocessing_metadata = json.load(f)
            self.debug(f"Features: {len(preprocessing_metadata['feature_columns'])}")
            
            # Verify feature count matches
            expected_features = len(preprocessing_metadata['feature_columns'])
            if X.shape[1] != expected_features:
                raise ValueError(f"Feature count mismatch: CSV has {X.shape[1]}, metadata says {expected_features}")
        else:
            preprocessing_metadata = None
        
        # Train the autoencoder with dynamic architecture
        self.debug("Training model...")
        model, encoding_dim, architecture = self.create_model(X.shape[1])
        
        model.fit(X, X,
                  epochs=self.epochs,
                  batch_size=min(self.batch_size, X.shape[0]),  # Don't exceed sample count
                  shuffle=self.shuffle,
                  verbose=self.model_training_verbosity)

        # Save the Keras model (disabled — the ONNX export below is used instead)
        # model.save(self.model_path)
        # self.debug(f"Saved model to {self.model_path}")
        
        # Export to ONNX for Rust
        self.export_to_onnx(model)
        
        # Calculate reconstruction errors
        reconstructions = model.predict(X, verbose=0)
        mse = np.mean(np.power(X - reconstructions, 2), axis=1)

        # Set threshold
        threshold = np.percentile(mse, 99)
        self.debug(f"Threshold for anomaly detection: {threshold}")

        anomalies = mse > threshold
        self.debug(f"Anomaly flags in training: {sum(anomalies)}")

        false_positive_rate = sum(anomalies) / int(X.shape[0])
        
        # Load or create preprocessing metadata
        if preprocessing_metadata is None:
            # If preprocessing metadata doesn't exist, create minimal version
            preprocessing_metadata = {
                "feature_columns": [f"feature_{i}" for i in range(X.shape[1])],
                "numeric_columns": [f"feature_{i}" for i in range(X.shape[1])],
                "categorical_valid_values": {},
                "missing_value_strategy": "fill_with_zero",
                "categorical_encoding": "one_hot",
                "scaling": "min_max_scaler"
            }
        
        # Create complete metadata file
        metadata = {
            "preprocessing": preprocessing_metadata,
            "training": {
                'training_samples': int(X.shape[0]),
                'false_positive_rate': float(false_positive_rate),
                'threshold': float(threshold),
                'score_range': [float(mse.min()), float(mse.max())],
                'model_type': 'Autoencoder',
                'model_params': {
                    "encoding_dim": encoding_dim,
                    "architecture": architecture,
                    "epochs": self.epochs,
                    "batch_size": self.batch_size,
                    "shuffle": self.shuffle,
                    "optimizer": self.optimizer,
                    "loss": self.loss
                }
            }
        }
        
        with open(self.metadata_path, 'w') as f:
            json.dump(metadata, f, indent=2)
        self.debug(f"Metadata saved to {self.metadata_path}")


def train_all_models(models_dir: str):
    """Train all models by reading preprocessed data from each subdirectory"""
    folders = ["CMD", "TLM"]
    
    trained_count = 0
    failed_count = 0
    
    for data_type in folders:
        type_dir = os.path.join(models_dir, data_type)
        if not os.path.exists(type_dir):
            continue
            
        for system_name in os.listdir(type_dir):
            system_dir = os.path.join(type_dir, system_name)
            
            if not os.path.isdir(system_dir):
                continue
                
            data_file = os.path.join(system_dir, "training_data.csv")
            
            if not os.path.exists(data_file):
                print(f"Warning: {data_file} not found, skipping...")
                continue
            
            print(f"\n{'='*60}")
            print(f"Training model: {data_type}_{system_name}")
            print(f"{'='*60}")
            
            try:
                model = AutoencoderForAnomalyDetection(system_dir, debug=True)
                model.train()
                
                print(f"Successfully trained {data_type}_{system_name}")
                trained_count += 1
            except Exception as e:
                print(f"Error training {data_type}_{system_name}: {e}")
                import traceback
                traceback.print_exc()
                failed_count += 1
    
    print(f"\n{'='*60}")
    print(f"Training Summary:")
    print(f"  Successfully trained: {trained_count} models")
    print(f"  Failed: {failed_count} models")
    print(f"{'='*60}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train anomaly detection models")
    parser.add_argument("--models-dir", default="scml_models", help="Directory containing model subdirectories")
    parser.add_argument("--train-only", action="store_true", help="Only train models (called from Rust)")
    
    args = parser.parse_args()
    
    if args.train_only:
        train_all_models(args.models_dir)
    else:
        print("Use --train-only flag when calling from Rust")
        sys.exit(1)