import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, RepeatVector, TimeDistributed
import os

def build_and_train_model(X_train):
    """Builds and trains the multi-feature LSTM autoencoder model."""
    if X_train is None or len(X_train) == 0:
        print("Training data is empty. Cannot build model.")
        return

    timesteps = X_train.shape[1]
    n_features = X_train.shape[2] # This will now be > 1
    
    # Define the model architecture
    model = Sequential([
        LSTM(128, activation='relu', input_shape=(timesteps, n_features), return_sequences=True),
        LSTM(64, activation='relu', return_sequences=False),
        RepeatVector(timesteps),
        LSTM(64, activation='relu', return_sequences=True),
        LSTM(128, activation='relu', return_sequences=True),
        TimeDistributed(Dense(n_features))
    ])
    
    model.compile(optimizer='adam', loss='mae')
    model.summary()
    
    print(f"\nTraining model with {n_features} features...")
    # Train the model
    model.fit(X_train, X_train, epochs=30, batch_size=64, validation_split=0.1, verbose=1)
    
    # Save the new multi-feature model
    os.makedirs('models', exist_ok=True)
    model.save('models/multi_feature_model.h5')
    print("\nNew multi-feature model saved successfully to models/multi_feature_model.h5")

if __name__ == '__main__':
    try:
        # MODIFIED: Load the new multi-feature data file
        training_data = np.load('data/multi_feature_sequences.npy')
        build_and_train_model(training_data)
    except FileNotFoundError:
        print("Error: 'multi_feature_sequences.npy' not found.")
        print("Please run the updated 'training_data_preparer.py' first.")