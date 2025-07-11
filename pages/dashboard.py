# pages/dashboard.py
import dash
from dash import dcc, html, Input, Output, State, ALL, ctx
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto
import plotly.graph_objects as go
import pandas as pd
from datetime import timedelta
from collections import Counter

from core_logic import analyze_live_traffic, query_api, INFLUX_BUCKET, INFLUX_ORG, ANOMALY_DETAILS
from helpers import get_geoip_details

dash.register_page(__name__, path='/')

modern_stylesheet = [
    {'selector': 'node', 'style': {'label': 'data(label)', 'color': '#fff', 'font-size': '14px'}},
    {'selector': 'edge', 'style': {'line-color': '#555', 'width': 2}},
    {'selector': '[id *= "192.168."]', 'style': {'background-color': '#FF851B', 'shape': 'star'}}
]

layout = dbc.Container([
    dbc.Row([
        dbc.Col([
            dbc.Card(dcc.Graph(id='traffic-chart'), className="card-style mb-4"),
            dbc.Card(dbc.CardBody([
                html.H4("Latest Anomaly Details (Last 10)"),
                html.Div(id='anomaly-table-container')
            ]), className="card-style"),
        ], md=8),
        dbc.Col([
            dbc.Card(dbc.CardBody([html.H4("Time Controls"), dcc.Dropdown(id='time-range-dropdown',
                options=[{'label': 'Last 5 Minutes', 'value': '-5m'}, {'label': 'Last Hour', 'value': '-1h'}],
                value='-5m')]), className="card-style mb-4"),
            dbc.Card(dbc.CardBody([html.H4("Live Stats"), html.Div(id='live-stats-panel')]), className="card-style mb-4"),
            dbc.Card(dbc.CardBody([html.H4("Anomaly Connection Graph"),
                cyto.Cytoscape(id='network-topology-graph', layout={'name': 'cose'},
                    stylesheet=modern_stylesheet, style={'width': '100%', 'height': '350px'})
            ]), className="card-style"),
        ], md=4),
    ]),
    dbc.Modal([
        dbc.ModalHeader(dbc.ModalTitle("Anomaly Details")),
        dbc.ModalBody(id="modal-body-content"),
        dbc.ModalFooter(dbc.Button("Close", id="modal-close-button", className="ml-auto")),
    ], id="details-modal", is_open=False, centered=True),
    dcc.Interval(id='interval-component', interval=5*1000, n_intervals=0)
], fluid=True)

# --- Callbacks for the dashboard page ---
@dash.callback(
    [Output('traffic-chart', 'figure'),
     Output('anomaly-table-container', 'children'),
     Output('live-stats-panel', 'children'),
     Output('network-topology-graph', 'elements')],
    [Input('interval-component', 'n_intervals'),
     Input('time-range-dropdown', 'value')]
)
def update_dashboard(n, time_range):
    analyze_live_traffic()
    
    traffic_query = f'from(bucket: "{INFLUX_BUCKET}") |> range(start: {time_range}) |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")'
    traffic_query_result = query_api.query_data_frame(org=INFLUX_ORG, query=traffic_query)

    fig = go.Figure(layout={"template": "plotly_dark", "paper_bgcolor": "rgba(0,0,0,0)", "plot_bgcolor": "rgba(0,0,0,0)"})
    df_hist = pd.DataFrame()
    if isinstance(traffic_query_result, list) and traffic_query_result: df_hist = pd.concat(traffic_query_result)
    elif isinstance(traffic_query_result, pd.DataFrame): df_hist = traffic_query_result

    total_packets = len(df_hist)
    if not df_hist.empty:
        fig.add_trace(go.Scatter(x=df_hist['_time'], y=df_hist['packet_size'], mode='lines', name='Traffic', line=dict(color='#00BFFF')))
    
    anomaly_records = list(ANOMALY_DETAILS)
    
    graph_elements, nodes = [], set()
    if anomaly_records:
        df_anomalies = pd.DataFrame(anomaly_records)
        df_anomalies['timestamp'] = pd.to_datetime(df_anomalies['timestamp'], unit='s').dt.tz_localize('UTC')
        
        time_delta_str = time_range.replace('-', '').replace('m', 'T').replace('h', 'H')
        time_filter_start = pd.Timestamp.now(tz='UTC') - pd.Timedelta(time_delta_str)
        anomalies_for_graph = df_anomalies[df_anomalies['timestamp'] >= time_filter_start]

        if not anomalies_for_graph.empty:
            fig.add_trace(go.Scatter(x=anomalies_for_graph['timestamp'], y=anomalies_for_graph['packet_size'],
                                     mode='markers', name='Anomaly', marker=dict(color='#FF4136', size=10, symbol='x')))

        for record in anomaly_records[:30]:
            src, dst = record['src_ip'], record['dst_ip']
            if src not in nodes: nodes.add(src); graph_elements.append({'data': {'id': src, 'label': src}})
            if dst not in nodes: nodes.add(dst); graph_elements.append({'data': {'id': dst, 'label': dst}})
            graph_elements.append({'data': {'source': src, 'target': dst}})

    fig.update_layout(title_text=f'Network Traffic for the {time_range.replace("-", "Last ")}')

    table_header = [html.Thead(html.Tr([
        html.Th("Timestamp"), html.Th("Source IP"), html.Th("Destination IP"),
        html.Th("Packet Size"), html.Th("Error Score"), html.Th("Threat Score"), html.Th("Action")
    ]))]
    
    table_rows = []
    for i, record in enumerate(anomaly_records[:10]):
        threat_style = {'color': '#FF4136', 'fontWeight': 'bold'} if record.get('threat_score', 0) > 25 else {}
        table_rows.append(html.Tr([
            html.Td(record.get('timestamp_str', 'N/A')),
            html.Td(record.get('src_ip', 'N/A')),
            html.Td(record.get('dst_ip', 'N/A')),
            html.Td(record.get('packet_size', 'N/A')),
            html.Td(record.get('reconstruction_error', 'N/A')),
            html.Td(record.get('threat_score', 'N/A'), style=threat_style),
            html.Td(dbc.Button("Details", id={'type': 'details-button', 'index': i}, size="sm", color="primary"))
        ]))
    
    anomaly_table = dbc.Table(table_header + [html.Tbody(table_rows)],
                              color="dark", striped=False, bordered=False, className="table-shimmer")
    
    stats_children = [html.P(f"Packets in View: {total_packets}"), html.P(f"Anomalies Found (session): {len(anomaly_records)}")]
    
    return fig, anomaly_table, stats_children, graph_elements

@dash.callback(
    [Output("details-modal", "is_open"), Output("modal-body-content", "children")],
    [Input({'type': 'details-button', 'index': ALL}, 'n_clicks')],
    prevent_initial_call=True
)
def open_modal(n_clicks):
    if not any(n_clicks):
        return False, None
    button_id_index = ctx.triggered_id['index']
    if button_id_index >= len(ANOMALY_DETAILS):
        return False, None
    full_record = ANOMALY_DETAILS[button_id_index]
    dst_ip = full_record.get('dst_ip', 'N/A')
    geoip_info = get_geoip_details(dst_ip)
    
    modal_content = html.Div([
        dbc.Row([dbc.Col(html.Strong("Timestamp:")), dbc.Col(full_record.get('timestamp_str', 'N/A'))]),
        dbc.Row([dbc.Col(html.Strong("Source IP:")), dbc.Col(full_record.get('src_ip', 'N/A'))]),
        dbc.Row([dbc.Col(html.Strong("Destination IP:")), dbc.Col(dst_ip)]),
        html.Hr(),
        dbc.Row([dbc.Col(html.Strong("Packet Size:")), dbc.Col(f"{full_record.get('packet_size', 'N/A')} bytes")]),
        dbc.Row([dbc.Col(html.Strong("Protocol:")), dbc.Col(full_record.get('protocol', 'N/A'))]),
        dbc.Row([dbc.Col(html.Strong("Destination Port:")), dbc.Col(full_record.get('dport', 'N/A'))]),
        dbc.Row([dbc.Col(html.Strong("Reconstruction Error:")), dbc.Col(full_record.get('reconstruction_error', 'N/A'))]),
        html.Hr(),
        dbc.Row([dbc.Col(html.Strong("Threat Score:")), dbc.Col(f"{full_record.get('threat_score', 'N/A')}% (AbuseIPDB)")]),
        dbc.Row([dbc.Col(html.Strong("IP Location:")), dbc.Col(f"{geoip_info.get('city', 'N/A')}, {geoip_info.get('country', 'N/A')}")]),
        dbc.Row([dbc.Col(html.Strong("ISP/Owner:")), dbc.Col(geoip_info.get('isp', 'N/A'))]),
    ])
    return True, modal_content

@dash.callback(
    Output("details-modal", "is_open", allow_duplicate=True),
    Input("modal-close-button", "n_clicks"),
    prevent_initial_call=True
)
def close_modal(n_clicks):
    if n_clicks:
        return False
    return dash.no_update