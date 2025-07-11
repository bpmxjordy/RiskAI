# training_data_preparer.py
import pandas as pd
import numpy as np
from influxdb_client import InfluxDBClient
from sklearn.preprocessing import MinMaxScaler
import os
import joblib

# --- InfluxDB Client Setup ---
from config import INFLUX_URL, INFLUX_TOKEN, INFLUX_ORG, INFLUX_BUCKET

influx_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
query_api = influx_client.query_api()

def create_sequences(data, time_steps=10):
    """Creates sequences from the time-series data."""
    sequences = []
    for i in range(len(data) - time_steps):
        sequences.append(data[i:(i + time_steps)])
    return np.array(sequences)

def get_training_data(time_range='-48h'):
    """Queries InfluxDB and prepares data for LSTM training."""
    print("Querying data from InfluxDB...")
    query = f'''
    from(bucket: "{INFLUX_BUCKET}")
    |> range(start: {time_range})
    |> filter(fn: (r) => r["_measurement"] == "network_packet")
    |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
    |> keep(columns: ["packet_size", "protocol", "dport"])
    '''
    query_result = query_api.query_data_frame(org=INFLUX_ORG, query=query)
    
    df = pd.DataFrame()
    if isinstance(query_result, list) and query_result:
        df = pd.concat(query_result).drop(columns=['result', 'table'])
    elif isinstance(query_result, pd.DataFrame):
        df = query_result.drop(columns=['result', 'table'])
    else:
        print("No data found.")
        return None, None

    print(f"Found {len(df)} data points.")
    
    # --- THIS IS THE FIX ---
    # 1. Handle missing values while the data is still 2D
    df = df.dropna()
    if df.empty:
        print("No usable data after dropping missing values.")
        return None, None

    # 2. Scale all three features
    features_to_scale = ['packet_size', 'protocol', 'dport']
    scaler = MinMaxScaler(feature_range=(0, 1))
    scaled_features = scaler.fit_transform(df[features_to_scale])
    
    # 3. Create sequences from the clean, scaled 2D data
    time_steps = 10
    sequences = create_sequences(scaled_features, time_steps)
    
    print(f"Created {len(sequences)} sequences with shape {sequences.shape}.")
    return sequences, scaler

if __name__ == '__main__':
    X_train, data_scaler = get_training_data()
    if X_train is not None:
        os.makedirs('data', exist_ok=True)
        os.makedirs('models', exist_ok=True)
        # Save the prepared data and the scaler object
        np.save('data/multi_feature_sequences.npy', X_train)
        joblib.dump(data_scaler, 'models/multi_feature_scaler.gz')
        print("Training data saved to 'data/multi_feature_sequences.npy'")
        print("Scaler saved to 'models/multi_feature_scaler.gz'")