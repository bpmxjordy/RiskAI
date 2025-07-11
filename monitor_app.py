import pandas as pd
import numpy as np
from dash import Dash, dcc, html, Input, Output, dash_table
import plotly.graph_objects as go
from scapy.all import sniff, IP
from threading import Thread, Lock
from collections import deque
import time
import requests
import json

# --- TensorFlow and Model Loading ---
import tensorflow as tf
from sklearn.preprocessing import MinMaxScaler

try:
    MODEL = tf.keras.models.load_model('models/lstm_autoencoder.h5', compile=False)
    print("LSTM Autoencoder model loaded successfully.")
except (IOError, ImportError):
    MODEL = None

# --- InfluxDB & AbuseIPDB Setup ---
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import ASYNCHRONOUS

INFLUX_URL = "http://localhost:8086"
INFLUX_TOKEN = "a6B-A04CNX28Phn5C1ussxY3b50wAVOW8PlaAl3zpKUDDFDi0m23bl30kVwPnaQkx8ILOObzGA_2rtas8YYFSQ=="
INFLUX_ORG = "RiskAI"
INFLUX_BUCKET = "network-traffic"

influx_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api = influx_client.write_api(write_options=ASYNCHRONOUS)
query_api = influx_client.query_api()

# --- Global Variables & Constants ---
TIME_STEPS = 10
PACKET_BUFFER = deque(maxlen=200)
ANOMALY_DETAILS = deque(maxlen=50)
CHECKED_IPS = {} # Cache for checked IPs
data_lock = Lock()
SCALER = MinMaxScaler(feature_range=(0, 1))
is_scaler_fitted = False
RECONSTRUCTION_THRESHOLD = 0.15

# --- Styling ---
CONTENT_STYLE = {"marginLeft": "2rem", "marginRight": "2rem", "padding": "2rem 1rem"}

# --- NEW: Threat Intelligence Function ---
def check_ip_threat(ip_address):
    if ip_address in CHECKED_IPS:
        return CHECKED_IPS[ip_address]
    
    if ip_address.startswith('192.168.') or ip_address.startswith('10.'): # Ignore local IPs
        return 0

    try:
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            params={'ipAddress': ip_address, 'maxAgeInDays': '90'},
            headers={'Accept': 'application/json', 'Key': "d8fc95ea9f41a8b9ff5b9f226b01d14c1a0faeb9a5c48b2455ce675fe26889604aae3f4b10d327d3"}
        )
        data = response.json()
        score = data.get('data', {}).get('abuseConfidenceScore', 0)
        CHECKED_IPS[ip_address] = score
        return score
    except requests.RequestException:
        return 0

# --- 1. Packet Sniffing ---
def packet_callback(packet):
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        packet_size = len(packet)

        p = Point("network_packet").tag("src_ip", src_ip).field("packet_size", packet_size)
        write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=p)

        with data_lock:
            PACKET_BUFFER.append({
                "timestamp": time.time(), "packet_size": packet_size,
                "src_ip": src_ip, "dst_ip": dst_ip
            })

# --- (Other functions like start_sniffing and analyze_live_traffic remain largely the same) ---
def start_sniffing():
    sniff(prn=packet_callback, store=False)

def analyze_live_traffic():
    global is_scaler_fitted
    with data_lock:
        if len(PACKET_BUFFER) < 50: return
        df = pd.DataFrame(list(PACKET_BUFFER))
        packet_sizes = df[['packet_size']].values
        if not is_scaler_fitted:
            scaled_sizes = SCALER.fit_transform(packet_sizes)
            is_scaler_fitted = True
        else:
            scaled_sizes = SCALER.transform(packet_sizes)
        
        sequences = [scaled_sizes[i: i + TIME_STEPS] for i in range(len(scaled_sizes) - TIME_STEPS + 1)]
        if not sequences: return

        sequences = np.array(sequences)
        predicted_sequences = MODEL.predict(sequences, verbose=0)
        mae_loss = np.mean(np.abs(predicted_sequences - sequences), axis=1)
        
        last_loss = mae_loss[-1][0]
        if last_loss > RECONSTRUCTION_THRESHOLD:
            anomaly_record = df.iloc[-1].to_dict()
            anomaly_record['reconstruction_error'] = round(last_loss, 4)
            anomaly_record['timestamp_str'] = pd.to_datetime(anomaly_record['timestamp'], unit='s').strftime('%H:%M:%S')
            
            # Add threat intel score
            threat_score = check_ip_threat(anomaly_record['dst_ip'])
            anomaly_record['threat_score'] = threat_score
            ANOMALY_DETAILS.appendleft(anomaly_record)

# --- 3. Visualization Dashboard ---
app = Dash(__name__, suppress_callback_exceptions=True)
# The app.layout and update_dashboard callback will need to be modified to include the new 'threat_score' field in the table and alerts.

app.layout = html.Div(style={'backgroundColor': '#111111', 'color': '#7FDBFF', 'fontFamily': 'Sans-Serif'}, children=[
    html.H1("AI Network Security Monitor", style={'textAlign': 'center', 'padding': '20px'}),
    html.Div([
        # Left Column
        html.Div([
            dcc.Graph(id='traffic-chart'),
            html.H3("Detected Anomaly Details"),
            dash_table.DataTable(id='anomaly-table',
                style_header={'backgroundColor': 'rgb(30, 30, 30)', 'color': 'white'},
                style_cell={'backgroundColor': 'rgb(50, 50, 50)', 'color': 'white', 'textAlign': 'left'},
                style_data_conditional=[{ # Highlight malicious IPs
                    'if': {'filter_query': '{threat_score} > 25', 'column_id': 'threat_score'},
                    'backgroundColor': '#FF4136', 'color': 'white'
                }]
            ),
        ], style={'width': '69%', 'display': 'inline-block', 'verticalAlign': 'top'}),
        # Right Column
        html.Div([
            html.H3("Controls"),
            dcc.Dropdown(id='time-range-dropdown',
                options=[{'label': 'Last 5 Minutes', 'value': '-5m'}, {'label': 'Last Hour', 'value': '-1h'}],
                value='-5m', style={'color': '#111111'}),
            html.Hr(),
            html.H3("Live Stats"),
            html.Div(id='live-stats-panel'),
            html.Hr(),
            html.H3("Alerts"),
            html.Div(id='alerts-panel'),
        ], style={'width': '29%', 'display': 'inline-block', 'paddingLeft': '2%', 'verticalAlign': 'top'}),
    ], style=CONTENT_STYLE),
    dcc.Interval(id='interval-component', interval=5*1000, n_intervals=0)
])

# The callback function needs to be updated to pass the new data to the table.
@app.callback(
    [Output('traffic-chart', 'figure'), Output('anomaly-table', 'data'),
     Output('anomaly-table', 'columns'), Output('live-stats-panel', 'children'),
     Output('alerts-panel', 'children')],
    [Input('interval-component', 'n_intervals'), Input('time-range-dropdown', 'value')]
)
def update_dashboard(n, time_range):
    if MODEL is not None:
        analyze_live_traffic()
    
    query = f'from(bucket: "{INFLUX_BUCKET}") |> range(start: {time_range}) |> filter(fn: (r) => r["_measurement"] == "network_packet") |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")'
    query_result = query_api.query_data_frame(org=INFLUX_ORG, query=query)
    
    fig = go.Figure()
    df_hist = pd.DataFrame()
    if isinstance(query_result, list) and query_result:
        df_hist = pd.concat(query_result)
    elif isinstance(query_result, pd.DataFrame):
        df_hist = query_result

    if not df_hist.empty:
        fig.add_trace(go.Scatter(x=df_hist['_time'], y=df_hist['packet_size'], mode='lines', name='Traffic', line=dict(color='#7FDBFF')))
    
    anomaly_records = list(ANOMALY_DETAILS)
    if anomaly_records:
        df_anomalies = pd.DataFrame(anomaly_records)
        df_anomalies['timestamp'] = pd.to_datetime(df_anomalies['timestamp'], unit='s')
        fig.add_trace(go.Scatter(x=df_anomalies['timestamp'], y=df_anomalies['packet_size'], mode='markers', name='Anomaly',
                                 marker=dict(color='#FF4136', size=10, symbol='x')))

    fig.update_layout(title=f'Network Traffic for the {time_range.replace("-", "Last ")}',
                      template="plotly_dark", xaxis_title="Time", yaxis_title="Packet Size (bytes)")

    table_data = []
    if anomaly_records:
        # Add the new 'threat_score' column
        table_df = pd.DataFrame(anomaly_records)[['timestamp_str', 'src_ip', 'dst_ip', 'packet_size', 'reconstruction_error', 'threat_score']]
        table_data = table_df.to_dict('records')
    
    table_columns = [{"name": i.replace("_", " ").title(), "id": i} for i in table_data[0].keys()] if table_data else []
    stats_children = [html.P(f"Buffer Size: {len(PACKET_BUFFER)}"), html.P(f"Anomalies Detected (session): {len(ANOMALY_DETAILS)}")]
    alerts_children = [html.P(f"{rec['timestamp_str']} - Anomaly from {rec['src_ip']} to {rec['dst_ip']} (Threat Score: {rec['threat_score']}%)") for rec in anomaly_records]

    return fig, table_data, table_columns, stats_children, alerts_children

# --- Main Execution ---
if __name__ == '__main__':
    sniffer_thread = Thread(target=start_sniffing, daemon=True)
    sniffer_thread.start()
    print("Starting Dash server...")
    app.run(debug=True, use_reloader=False)