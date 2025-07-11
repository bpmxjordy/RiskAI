# config.py

# --- InfluxDB & AbuseIPDB Setup ---
INFLUX_URL = "http://localhost:8086"
INFLUX_TOKEN = "a6B-A04CNX28Phn5C1ussxY3b50wAVOW8PlaAl3zpKUDDFDi0m23bl30kVwPnaQkx8ILOObzGA_2rtas8YYFSQ=="
INFLUX_ORG = "RiskAI"
INFLUX_BUCKET = "network-traffic"
ABUSEIPDB_KEY = "d8fc95ea9f41a8b9ff5b9f226b01d14c1a0faeb9a5c48b2455ce675fe26889604aae3f4b10d327d3"

# --- Model & Scaler Paths ---
MODEL_PATH = 'models/multi_feature_model.h5'
SCALER_PATH = 'models/multi_feature_scaler.gz'

# --- App Constants ---
TIME_STEPS = 10
RECONSTRUCTION_THRESHOLD = 0.07