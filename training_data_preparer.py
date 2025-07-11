import pandas as pd
import numpy as np
from influxdb_client import InfluxDBClient
from sklearn.preprocessing import MinMaxScaler
import os

# ... (InfluxDB setup is the same) ...
INFLUX_URL = "http://localhost:8086"
INFLUX_TOKEN = "a6B-A04CNX28Phn5C1ussxY3b50wAVOW8PlaAl3zpKUDDFDi0m23bl30kVwPnaQkx8ILOObzGA_2rtas8YYFSQ=="
INFLUX_ORG = "RiskAI"
INFLUX_BUCKET = "network-traffic"

influx_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
query_api = influx_client.query_api()


def create_sequences(data, time_steps=10):
    sequences = []
    for i in range(len(data) - time_steps):
        sequences.append(data[i:(i + time_steps)])
    return np.array(sequences)

def get_training_data(time_range='-24h'):
    print("Querying data from InfluxDB...")
    query = f'''
    from(bucket: "{INFLUX_BUCKET}")
    |> range(start: {time_range})
    |> filter(fn: (r) => r["_measurement"] == "network_packet")
    |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
    |> keep(columns: ["packet_size"])
    '''
    df = query_api.query_data_frame(org=INFLUX_ORG, query=query)
    
    if df.empty:
        print("No data found.")
        return None, None

    print(f"Found {len(df)} data points.")
    
    scaler = MinMaxScaler(feature_range=(0, 1))
    df['packet_size_scaled'] = scaler.fit_transform(df[['packet_size']])
    
    time_steps = 10
    sequences = create_sequences(df['packet_size_scaled'].values, time_steps)
    
    # --- THIS IS THE FIX ---
    # Reshape to 3D: [samples, timesteps, features]
    sequences = np.reshape(sequences, (sequences.shape[0], sequences.shape[1], 1))
    
    print(f"Created {len(sequences)} sequences with shape {sequences.shape}.")
    return sequences, scaler

if __name__ == '__main__':
    X_train, data_scaler = get_training_data()
    if X_train is not None:
        os.makedirs('data', exist_ok=True)
        np.save('data/training_sequences.npy', X_train)
        print("Training data saved to data/training_sequences.npy")