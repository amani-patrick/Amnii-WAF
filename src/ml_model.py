import tensorflow as tf
import numpy as np
import json
import logging
import os
from typing import Dict, Tuple, List
from .config import settings

logger = logging.getLogger(__name__)

class WAFMLModel:
    def __init__(self):
        self.model = None
        self.tokenizer = tf.keras.preprocessing.text.Tokenizer(num_words=10000, oov_token="<OOV>")
        self.max_sequence_length = 1000
        self.embedding_dim = 64
        self.model_path = settings.ML_MODEL_PATH
        self.tokenizer_path = self.model_path.replace(".h5", "_tokenizer.json")

        self._load_model()

    def _load_model(self):
        """Load model and tokenizer if available, otherwise create a new one"""
        try:
            if os.path.exists(self.model_path):
                self.model = tf.keras.models.load_model(self.model_path)
                logger.info("✅ Loaded existing ML model.")
            else:
                logger.info("🔄 No model found. Creating new model.")
                self._create_model()

            if os.path.exists(self.tokenizer_path):
                with open(self.tokenizer_path, "r") as f:
                    self.tokenizer = tf.keras.preprocessing.text.tokenizer_from_json(f.read())
                logger.info("✅ Loaded existing tokenizer.")
        except Exception as e:
            logger.error(f"⚠️ Error loading ML model: {str(e)}")
            self._create_model()

    def _create_model(self):
        """Create a CNN-LSTM based model for HTTP request anomaly detection"""
        self.model = tf.keras.Sequential([
            tf.keras.layers.Embedding(input_dim=10000, output_dim=self.embedding_dim, input_length=self.max_sequence_length),
            tf.keras.layers.Conv1D(64, 5, activation='relu'),
            tf.keras.layers.MaxPooling1D(2),
            tf.keras.layers.Conv1D(32, 3, activation='relu'),
            tf.keras.layers.MaxPooling1D(2),
            tf.keras.layers.LSTM(32, return_sequences=True),
            tf.keras.layers.LSTM(16),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dropout(0.5),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])
        self.model.compile(optimizer='adam', loss='binary_crossentropy', metrics=['accuracy'])
        logger.info("✅ Created new model.")

    def _preprocess_request(self, request_data: Dict) -> np.ndarray:
        """Convert request data to model input format"""
        request_str = json.dumps({
            'method': request_data.get('method', ''),
            'path': request_data.get('path', ''),
            'headers': request_data.get('headers', {}),
            'query_params': request_data.get('query_params', {}),
            'body': request_data.get('body', '')
        })

        if not self.tokenizer.word_index:
            self.tokenizer.fit_on_texts([request_str])  # Fit only if untrained

        sequence = self.tokenizer.texts_to_sequences([request_str])

        # Pad sequence
        padded = tf.keras.preprocessing.sequence.pad_sequences(
            sequence, maxlen=self.max_sequence_length, padding='post', truncating='post'
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
            input_data = self._preprocess_request(request_data)
            prediction = self.model.predict(input_data, verbose=0)[0][0]
            is_malicious = prediction >= settings.PREDICTION_THRESHOLD

            if is_malicious:
                logger.warning(f"🚨 ML model detected malicious request with {prediction:.2%} confidence")

            return is_malicious, float(prediction)

        except Exception as e:
            logger.error(f"⚠️ Error in ML prediction: {str(e)}")
            return False, 0.0

    def train(self, training_data: List[Dict], labels: List[int], epochs: int = 10, batch_size: int = 32):
        """Train the model on new data"""
        try:
            processed_data = np.vstack([self._preprocess_request(req) for req in training_data])
            labels = np.array(labels)

            history = self.model.fit(
                processed_data, labels, epochs=epochs, batch_size=batch_size, validation_split=0.2, verbose=1
            )

            # Save model & tokenizer
            self.model.save(self.model_path)
            with open(self.tokenizer_path, "w") as f:
                f.write(self.tokenizer.to_json())

            logger.info("✅ Model training completed successfully.")
            return history.history

        except Exception as e:
            logger.error(f"⚠️ Error training model: {str(e)}")
            return None

    def evaluate(self, test_data: List[Dict], labels: List[int]) -> Dict:
        """Evaluate model performance on test data"""
        try:
            processed_data = np.vstack([self._preprocess_request(req) for req in test_data])
            labels = np.array(labels)

            loss, accuracy = self.model.evaluate(processed_data, labels, verbose=0)

            return {'loss': float(loss), 'accuracy': float(accuracy)}

        except Exception as e:
            logger.error(f"⚠️ Error evaluating model: {str(e)}")
            return None
