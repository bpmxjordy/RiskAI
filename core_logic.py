# core_logic.py
import time
import pandas as pd
import numpy as np
from scapy.all import sniff, IP, TCP, UDP
from collections import deque
from threading import Lock
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import ASYNCHRONOUS
import tensorflow as tf
import joblib

from config import INFLUX_URL, INFLUX_TOKEN, INFLUX_ORG, INFLUX_BUCKET, MODEL_PATH, SCALER_PATH, TIME_STEPS, RECONSTRUCTION_THRESHOLD
from helpers import check_ip_threat, get_geoip_details

# --- Load Model and Scaler ---
try:
    MODEL = tf.keras.models.load_model(MODEL_PATH, compile=False)
    SCALER = joblib.load(SCALER_PATH)
    print("✅ Model and Scaler loaded successfully.")
except Exception as e:
    print(f"❌ Error during initialization: {e}")
    MODEL, SCALER = None, None

# --- Global Variables ---
PACKET_BUFFER = deque(maxlen=2000)
ANOMALY_DETAILS = deque(maxlen=250)
data_lock = Lock()

# --- InfluxDB Client ---
influx_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api = influx_client.write_api(write_options=ASYNCHRONOUS)
query_api = influx_client.query_api()

# --- Core Functions ---
def packet_callback(packet):
    if IP in packet:
        dst_ip, src_ip, packet_size, proto, dport = packet[IP].dst, packet[IP].src, len(packet), packet.proto, 0
        if TCP in packet: dport = packet[TCP].dport
        elif UDP in packet: dport = packet[UDP].dport
        p = Point("network_packet").tag("src_ip", src_ip).tag("dst_ip", dst_ip).field("packet_size", packet_size).field("protocol", proto).field("dport", dport)
        write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=p)
        with data_lock:
            geoip = get_geoip_details(dst_ip)
            PACKET_BUFFER.append({
                "timestamp": time.time(), "packet_size": packet_size,
                "src_ip": src_ip, "dst_ip": dst_ip,
                "protocol": proto, "dport": dport,
                "country": geoip.get("country", "N/A")
            })

def start_sniffing():
    sniff(prn=packet_callback, store=False)

def analyze_live_traffic():
    with data_lock:
        if len(PACKET_BUFFER) < 50 or SCALER is None or MODEL is None: return
        df = pd.DataFrame(list(PACKET_BUFFER))
        features_to_scale = ['packet_size', 'protocol', 'dport']
        scaled_features = SCALER.transform(df[features_to_scale])
        sequences = np.array([scaled_features[i: i + TIME_STEPS] for i in range(len(scaled_features) - TIME_STEPS + 1)])
        if len(sequences) == 0: return
        
        predicted_sequences = MODEL.predict(sequences, verbose=0)
        mae_loss = np.mean(np.abs(predicted_sequences - sequences), axis=1)
        
        last_loss = np.mean(mae_loss[-1])
        if last_loss > RECONSTRUCTION_THRESHOLD:
            anomaly_record = df.iloc[-1].to_dict()
            anomaly_record['reconstruction_error'] = round(last_loss, 4)
            anomaly_record['timestamp_str'] = pd.to_datetime(anomaly_record['timestamp'], unit='s').strftime('%H:%M:%S')
            is_duplicate = any(r['timestamp_str'] == anomaly_record['timestamp_str'] and r['src_ip'] == anomaly_record['src_ip'] for r in ANOMALY_DETAILS)
            if not is_duplicate:
                anomaly_record['threat_score'] = check_ip_threat(anomaly_record['dst_ip'])
                anomaly_record['geoip'] = get_geoip_details(anomaly_record['dst_ip'])
                ANOMALY_DETAILS.appendleft(anomaly_record)
                p = Point("detected_anomaly").time(pd.to_datetime(anomaly_record['timestamp'], unit='s')).tag("src_ip", anomaly_record['src_ip']).tag("dst_ip", anomaly_record['dst_ip']).field("packet_size", int(anomaly_record['packet_size'])).field("reconstruction_error", anomaly_record['reconstruction_error']).field("threat_score", anomaly_record['threat_score']).field("country", anomaly_record['geoip'].get('country', 'N/A'))
                write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=p)