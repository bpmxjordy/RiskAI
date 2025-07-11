import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, RepeatVector, TimeDistributed

def build_and_train_model(X_train):
    """Builds and trains the LSTM autoencoder model."""
    if X_train is None or len(X_train) == 0:
        print("Training data is empty. Cannot build model.")
        return

    timesteps = X_train.shape[1]
    n_features = X_train.shape[2]
    
    # Reshape X_train for LSTM [samples, timesteps, features]
    X_train = X_train.reshape((X_train.shape[0], timesteps, n_features))
    
    # Define the model
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
    
    print("\nTraining model...")
    # Train the model
    model.fit(X_train, X_train, epochs=20, batch_size=32, validation_split=0.1, verbose=1)
    
    # Save the trained model
    model.save('models/lstm_autoencoder.h5')
    print("\nModel saved successfully to models/lstm_autoencoder.h5")

if __name__ == '__main__':
    try:
        training_data = np.load('data/training_sequences.npy')
        build_and_train_model(training_data)
    except FileNotFoundError:
        print("Error: training_sequences.npy not found.")
        print("Please run training_data_preparer.py first to generate the data.")