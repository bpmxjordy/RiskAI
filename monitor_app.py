import pandas as pd
import numpy as np
from dash import Dash, dcc, html, Input, Output, State, dash_table, ctx
import plotly.graph_objects as go
from scapy.all import sniff, IP, TCP, UDP
from threading import Thread, Lock
from collections import deque
import time
import requests
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto
import joblib

# --- TensorFlow and Model Loading ---
import tensorflow as tf
from sklearn.preprocessing import MinMaxScaler

try:
    MODEL = tf.keras.models.load_model('models/multi_feature_model.h5', compile=False)
    SCALER = joblib.load('models/multi_feature_scaler.gz')
    print("Multi-feature LSTM model and scaler loaded successfully.")
except (IOError, ImportError):
    MODEL = None
    SCALER = None

# --- InfluxDB & AbuseIPDB Setup ---
from influxdb_client import InfluxDBClient, Point
from influxdb_client.client.write_api import ASYNCHRONOUS

INFLUX_URL = "http://localhost:8086"
INFLUX_TOKEN = "a6B-A04CNX28Phn5C1ussxY3b50wAVOW8PlaAl3zpKUDDFDi0m23bl30kVwPnaQkx8ILOObzGA_2rtas8YYFSQ=="
INFLUX_ORG = "RiskAI"
INFLUX_BUCKET = "network-traffic"
ABUSEIPDB_KEY = "d8fc95ea9f41a8b9ff5b9f226b01d14c1a0faeb9a5c48b2455ce675fe26889604aae3f4b10d327d3"

influx_client = InfluxDBClient(url=INFLUX_URL, token=INFLUX_TOKEN, org=INFLUX_ORG)
write_api = influx_client.write_api(write_options=ASYNCHRONOUS)
query_api = influx_client.query_api()

# --- Global Variables & Constants ---
TIME_STEPS = 10
PACKET_BUFFER = deque(maxlen=500)
ANOMALY_DETAILS = deque(maxlen=100)
CHECKED_IPS = {}
data_lock = Lock()
RECONSTRUCTION_THRESHOLD = 0.15

# --- Styling & Helper Functions ---
CONTENT_STYLE = {"marginLeft": "2rem", "marginRight": "2rem", "padding": "2rem 1rem"}
default_stylesheet = [
    {'selector': 'node', 'style': {'label': 'data(label)', 'color': 'white', 'background-color': '#0074D9'}},
    {'selector': 'edge', 'style': {'line-color': '#555', 'width': 2}},
    {'selector': '[id *= "192.168."]', 'style': {'background-color': '#FF851B', 'shape': 'star'}}
]

def check_ip_threat(ip_address):
    if ip_address in CHECKED_IPS and 'threat_score' in CHECKED_IPS[ip_address]: return CHECKED_IPS[ip_address]['threat_score']
    if ip_address.startswith(('192.168.', '10.')): return 0
    try:
        response = requests.get('https://api.abuseipdb.com/api/v2/check', params={'ipAddress': ip_address, 'maxAgeInDays': '90'}, headers={'Accept': 'application/json', 'Key': ABUSEIPDB_KEY})
        score = response.json().get('data', {}).get('abuseConfidenceScore', 0)
        if ip_address not in CHECKED_IPS: CHECKED_IPS[ip_address] = {}
        CHECKED_IPS[ip_address]['threat_score'] = score
        return score
    except requests.RequestException: return 0

def get_geoip_details(ip_address):
    if ip_address in CHECKED_IPS and 'geoip' in CHECKED_IPS[ip_address]: return CHECKED_IPS[ip_address]['geoip']
    if ip_address.startswith(('192.168.', '10.')): return {"country": "Private Network", "city": "-", "isp": "Local"}
    try:
        response = requests.get(f"http://ip-api.com/json/{ip_address}")
        data = response.json()
        details = {"country": data.get("country", "N/A"), "city": data.get("city", "N/A"), "isp": data.get("isp", "N/A")}
        if ip_address not in CHECKED_IPS: CHECKED_IPS[ip_address] = {}
        CHECKED_IPS[ip_address]['geoip'] = details
        return details
    except requests.RequestException: return {"country": "Error", "city": "Error", "isp": "Error"}

# --- Core Logic ---
def packet_callback(packet):
    if IP in packet:
        dst_ip, src_ip, packet_size, proto, dport = packet[IP].dst, packet[IP].src, len(packet), packet.proto, 0
        if TCP in packet: dport = packet[TCP].dport
        elif UDP in packet: dport = packet[UDP].dport
        
        p = Point("network_packet").tag("src_ip", src_ip).tag("dst_ip", dst_ip).field("packet_size", packet_size).field("protocol", proto).field("dport", dport)
        write_api.write(bucket=INFLUX_BUCKET, org=INFLUX_ORG, record=p)

        with data_lock:
            # --- THIS IS THE FIX ---
            # Get GeoIP details for every packet to populate the summary table
            geoip = get_geoip_details(dst_ip)
            PACKET_BUFFER.append({
                "timestamp": time.time(), "packet_size": packet_size,
                "src_ip": src_ip, "dst_ip": dst_ip,
                "protocol": proto, "dport": dport,
                "country": geoip.get("country", "N/A") # Add country to the buffer
            })

def start_sniffing():
    sniff(prn=packet_callback, store=False)

def analyze_live_traffic():
    with data_lock:
        if len(PACKET_BUFFER) < 50 or SCALER is None: return
        df = pd.DataFrame(list(PACKET_BUFFER))
        
        features_to_scale = ['packet_size', 'protocol', 'dport']
        scaled_features = SCALER.transform(df[features_to_scale])
        
        sequences = [scaled_features[i: i + TIME_STEPS] for i in range(len(scaled_features) - TIME_STEPS + 1)]
        if not sequences: return
        
        sequences = np.array(sequences)
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

# --- Visualization Dashboard ---
app = Dash(__name__, suppress_callback_exceptions=True, external_stylesheets=[dbc.themes.DARKLY])
app.layout = html.Div([
    dcc.Store(id='graph-filter-store'),
    html.H1("AI Network Security Monitor", style={'textAlign': 'center', 'padding': '20px'}),
    html.Div([
        html.Div([
            dcc.Graph(id='traffic-chart'),
            dbc.Button("Reset Graph View", id="reset-graph-button", color="primary", className="mt-2 mb-2"),
            html.H3("Detected Anomaly Details"),
            dash_table.DataTable(id='anomaly-table',
                style_header={'backgroundColor': 'rgb(30, 30, 30)', 'color': 'white'},
                style_cell={'backgroundColor': 'rgb(50, 50, 50)', 'color': 'white', 'textAlign': 'left', 'border': '1px solid #555'},
                style_data_conditional=[{'if': {'filter_query': '{threat_score} > 25', 'column_id': 'threat_score'}, 'backgroundColor': '#FF4136', 'color': 'white'}],
                markdown_options={"html": True}
            ),
        ], style={'width': '69%', 'display': 'inline-block', 'verticalAlign': 'top'}),
        html.Div([
            dbc.Card([dbc.CardBody([html.H4("Time Controls"), dcc.Dropdown(id='time-range-dropdown',
                options=[{'label': 'Last 5 Minutes', 'value': '-5m'}, {'label': 'Last Hour', 'value': '-1h'}], value='-5m')])]),
            dbc.Card([dbc.CardBody([html.H4("Live Stats"), html.Div(id='live-stats-panel')])], className="mt-3"),
            dbc.Card([dbc.CardBody([html.H4("Top Countries by Traffic"),
                                     dash_table.DataTable(id='country-summary-table',
                                         style_header={'backgroundColor': 'rgb(30, 30, 30)', 'color': 'white'},
                                         style_cell={'backgroundColor': 'rgb(50, 50, 50)', 'color': 'white', 'textAlign': 'left', 'border': '1px solid #555'},
                                         markdown_options={"html": True})
                                     ])], className="mt-3"),
            dbc.Card([dbc.CardBody([html.H4("Anomaly Connection Graph"),
                                     cyto.Cytoscape(id='network-topology-graph', layout={'name': 'cose'},
                                         style={'width': '100%', 'height': '250px'}, stylesheet=default_stylesheet)
                                     ])], className="mt-3"),
        ], style={'width': '29%', 'display': 'inline-block', 'paddingLeft': '2%', 'verticalAlign': 'top'}),
    ], style=CONTENT_STYLE),
    dbc.Modal([dbc.ModalHeader("Anomaly Details"), dbc.ModalBody(id="modal-body-content"),
               dbc.ModalFooter(dbc.Button("Close", id="modal-close-button", className="ml-auto"))], id="details-modal", is_open=False),
    dcc.Interval(id='interval-component', interval=5*1000, n_intervals=0)
])

# --- Callbacks ---
@app.callback(
    Output('graph-filter-store', 'data'),
    [Input('country-summary-table', 'active_cell'), Input('reset-graph-button', 'n_clicks')],
    [State('country-summary-table', 'data')],
    prevent_initial_call=True
)
def update_graph_filter(active_cell, n_clicks, table_data):
    if ctx.triggered_id == 'reset-graph-button':
        return None
    if ctx.triggered_id == 'country-summary-table' and active_cell and table_data and active_cell['column_id'] == 'Action':
        return {'type': 'country', 'value': table_data[active_cell['row']]['Country']}
    return None

@app.callback(
    [Output('traffic-chart', 'figure'), Output('anomaly-table', 'data'),
     Output('anomaly-table', 'columns'), Output('live-stats-panel', 'children'),
     Output('country-summary-table', 'data'), Output('country-summary-table', 'columns'),
     Output('network-topology-graph', 'elements')],
    [Input('interval-component', 'n_intervals'), Input('time-range-dropdown', 'value'),
     Input('graph-filter-store', 'data')]
)
def update_dashboard(n, time_range, graph_filter):
    if MODEL is not None: analyze_live_traffic()
    
    query = f'from(bucket: "{INFLUX_BUCKET}") |> range(start: {time_range}) |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")'
    query_result = query_api.query_data_frame(org=INFLUX_ORG, query=query)
    
    fig = go.Figure(layout={"template": "plotly_dark"})
    df_hist = pd.DataFrame()
    if isinstance(query_result, list) and query_result: df_hist = pd.concat(query_result)
    elif isinstance(query_result, pd.DataFrame): df_hist = query_result

    if not df_hist.empty:
        fig.add_trace(go.Scatter(x=df_hist['_time'], y=df_hist['packet_size'], mode='lines', name='Traffic', line=dict(color='#7FDBFF')))
    
    anomaly_records = list(ANOMALY_DETAILS)
    graph_elements, nodes = [], set()
    if anomaly_records:
        df_anomalies = pd.DataFrame(anomaly_records)
        df_anomalies['timestamp'] = pd.to_datetime(df_anomalies['timestamp'], unit='s')
        
        anomalies_to_highlight = df_anomalies
        highlight_name = "Anomaly"
        if graph_filter and graph_filter.get('type') == 'country':
             country = graph_filter.get('value')
             anomalies_to_highlight = df_anomalies[df_anomalies['country'] == country]
             highlight_name = f'{country} Anomalies'
        
        if not anomalies_to_highlight.empty:
            fig.add_trace(go.Scatter(x=anomalies_to_highlight['timestamp'], y=anomalies_to_highlight['packet_size'],
                                     mode='markers', name=highlight_name, marker=dict(color='yellow', size=12, symbol='star')))

        for record in anomaly_records:
            src, dst = record['src_ip'], record['dst_ip']
            if src not in nodes:
                nodes.add(src)
                graph_elements.append({'data': {'id': src, 'label': src}})
            if dst not in nodes:
                nodes.add(dst)
                graph_elements.append({'data': {'id': dst, 'label': dst}})
            graph_elements.append({'data': {'source': src, 'target': dst}})

    fig.update_layout(title_text=f'Network Traffic for the {time_range.replace("-", "Last ")}',
                      xaxis_title_text="Time", yaxis_title_text="Packet Size (bytes)")

    if anomaly_records:
        df_anomalies['Details'] = "<button>Details</button>"
        table_df = df_anomalies[['timestamp_str', 'src_ip', 'dst_ip', 'packet_size', 'reconstruction_error', 'threat_score', 'Details']]
        table_data = table_df.to_dict('records')
    else:
        table_data = []
    table_columns = [{"name": i.replace("_", " ").title(), "id": i, "presentation": "markdown"} for i in table_data[0].keys()] if table_data else []

    country_summary_data = []
    with data_lock:
        if PACKET_BUFFER:
            summary_df = pd.DataFrame(list(PACKET_BUFFER))
            if not summary_df.empty:
                country_summary = summary_df.groupby('country').agg(packet_count=('packet_size', 'count')).reset_index().sort_values('packet_count', ascending=False)
                country_summary.rename(columns={'packet_count': 'Packet Count', 'country': 'Country'}, inplace=True)
                country_summary['Action'] = "<button>View</button>"
                country_summary_data = country_summary.to_dict('records')
            
    country_summary_columns = [{"name": i, "id": i, "presentation": "markdown"} for i in country_summary_data[0].keys()] if country_summary_data else []

    stats_children = [html.P(f"Buffer Size: {len(PACKET_BUFFER)}"), html.P(f"Anomalies Detected (session): {len(ANOMALY_DETAILS)}")]
    
    return fig, table_data, table_columns, stats_children, country_summary_data, country_summary_columns, graph_elements

@app.callback(
    [Output("details-modal", "is_open"), Output("modal-body-content", "children")],
    [Input("anomaly-table", "active_cell")],
    [State("anomaly-table", "data")]
)
def open_modal(active_cell, table_data):
    if not active_cell or not table_data or active_cell['column_id'] != 'Details':
        return False, None

    row_data = table_data[active_cell['row']]
    dst_ip = row_data['dst_ip']
    geoip_info = get_geoip_details(dst_ip)
    
    modal_content = html.Div([
        dbc.Row([dbc.Col(html.Strong("Timestamp:")), dbc.Col(row_data['timestamp_str'])]),
        dbc.Row([dbc.Col(html.Strong("Source IP:")), dbc.Col(row_data['src_ip'])]),
        dbc.Row([dbc.Col(html.Strong("Destination IP:")), dbc.Col(dst_ip)]),
        html.Hr(),
        dbc.Row([dbc.Col(html.Strong("Packet Size:")), dbc.Col(f"{row_data['packet_size']} bytes")]),
        dbc.Row([dbc.Col(html.Strong("Reconstruction Error:")), dbc.Col(row_data.get('reconstruction_error', 'N/A'))]),
        html.Hr(),
        dbc.Row([dbc.Col(html.Strong("Threat Score:")), dbc.Col(f"{row_data['threat_score']}% (AbuseIPDB)")]),
        dbc.Row([dbc.Col(html.Strong("IP Location:")), dbc.Col(f"{geoip_info.get('city', 'N/A')}, {geoip_info.get('country', 'N/A')}")]),
        dbc.Row([dbc.Col(html.Strong("ISP/Owner:")), dbc.Col(geoip_info.get('isp', 'N/A'))]),
    ])
    return True, modal_content

@app.callback(
    Output("details-modal", "is_open", allow_duplicate=True),
    [Input("modal-close-button", "n_clicks")],
    [State("details-modal", "is_open")],
    prevent_initial_call=True
)
def close_modal(n, is_open):
    if n: return not is_open
    return is_open

# --- Main Execution ---
if __name__ == '__main__':
    sniffer_thread = Thread(target=start_sniffing, daemon=True)
    print("Starting packet sniffer...")
    sniffer_thread.start()
    print("Starting Dash server...")
    app.run(debug=True, use_reloader=False)