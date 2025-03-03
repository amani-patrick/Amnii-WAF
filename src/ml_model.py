import tensorflow as tf
import numpy as np
from typing import Dict, Tuple, List
import json
import logging
from .config import settings

logger = logging.getLogger(__name__)

class WAFMLModel:
    def __init__(self):
        self.model = None
        self.tokenizer = None
        self.max_sequence_length = 1000
        self.vocab_size = 10000
        self.embedding_dim = 64
        self._load_model()
        
    def _load_model(self):
        """Load or create the TensorFlow model"""
        try:
            self.model = tf.keras.models.load_model(settings.ML_MODEL_PATH)
            logger.info("Loaded existing model from disk")
        except:
            logger.info("Creating new model")
            self._create_model()
            
    def _create_model(self):
        """Create a new model for HTTP request anomaly detection"""
        self.model = tf.keras.Sequential([
            # Embedding layer for text input
            tf.keras.layers.Embedding(
                input_dim=self.vocab_size,
                output_dim=self.embedding_dim,
                input_length=self.max_sequence_length
            ),
            
            # Convolutional layers for feature extraction
            tf.keras.layers.Conv1D(64, 5, activation='relu'),
            tf.keras.layers.MaxPooling1D(2),
            tf.keras.layers.Conv1D(32, 3, activation='relu'),
            tf.keras.layers.MaxPooling1D(2),
            
            # LSTM layer for sequence processing
            tf.keras.layers.LSTM(32, return_sequences=True),
            tf.keras.layers.LSTM(16),
            
            # Dense layers for classification
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dropout(0.5),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        
        self.model.compile(
            optimizer='adam',
            loss='binary_crossentropy',
            metrics=['accuracy']
        )
        
    def _preprocess_request(self, request_data: Dict) -> np.ndarray:
        """Convert request data to model input format"""
        # Convert request to string representation
        request_str = json.dumps({
            'method': request_data.get('method', ''),
            'path': request_data.get('path', ''),
            'headers': request_data.get('headers', {}),
            'query_params': request_data.get('query_params', {}),
            'body': request_data.get('body', '')
        })
        
        # Tokenize if tokenizer exists
        if self.tokenizer is None:
            self.tokenizer = tf.keras.preprocessing.text.Tokenizer(
                num_words=self.vocab_size
            )
            self.tokenizer.fit_on_texts([request_str])
            
        # Convert to sequence
        sequence = self.tokenizer.texts_to_sequences([request_str])
        
        # Pad sequence
        padded = tf.keras.preprocessing.sequence.pad_sequences(
            sequence,
            maxlen=self.max_sequence_length,
            padding='post',
            truncating='post'
        )
        
        return padded
        
    def predict(self, request_data: Dict) -> Tuple[bool, float]:
        """
        Predict if a request is malicious
        Returns: (is_malicious, confidence)
        """
        if not settings.ENABLE_ML_DETECTION:
            return False, 0.0
            
        try:
            # Preprocess request
            input_data = self._preprocess_request(request_data)
            
            # Get prediction
            prediction = self.model.predict(input_data, verbose=0)[0][0]
            
            # Determine if request is malicious based on threshold
            is_malicious = prediction >= settings.PREDICTION_THRESHOLD
            
            if is_malicious:
                logger.warning(
                    f"ML model detected malicious request with {prediction:.2%} confidence"
                )
            
            return is_malicious, float(prediction)
            
        except Exception as e:
            logger.error(f"Error in ML prediction: {str(e)}")
            return False, 0.0
            
    def train(self, training_data: List[Dict], labels: List[int], epochs: int = 10):
        """Train the model on new data"""
        try:
            # Preprocess training data
            processed_data = np.vstack([
                self._preprocess_request(req) for req in training_data
            ])
            
            # Convert labels to numpy array
            labels = np.array(labels)
            
            # Train the model
            history = self.model.fit(
                processed_data,
                labels,
                epochs=epochs,
                validation_split=0.2,
                verbose=1
            )
            
            # Save the updated model
            self.model.save(settings.ML_MODEL_PATH)
            
            logger.info("Model training completed successfully")
            return history.history
            
        except Exception as e:
            logger.error(f"Error training model: {str(e)}")
            return None
            
    def evaluate(self, test_data: List[Dict], labels: List[int]) -> Dict:
        """Evaluate model performance on test data"""
        try:
            # Preprocess test data
            processed_data = np.vstack([
                self._preprocess_request(req) for req in test_data
            ])
            
            # Convert labels to numpy array
            labels = np.array(labels)
            
            # Evaluate model
            loss, accuracy = self.model.evaluate(processed_data, labels, verbose=0)
            
            return {
                'loss': float(loss),
                'accuracy': float(accuracy)
            }
            
        except Exception as e:
            logger.error(f"Error evaluating model: {str(e)}")
            return None
