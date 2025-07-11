# callbacks.py
import pandas as pd
import plotly.graph_objects as go
from dash import html, Input, Output, State, ctx
import dash_bootstrap_components as dbc
from datetime import timedelta

from core_logic import analyze_live_traffic, query_api, INFLUX_BUCKET, INFLUX_ORG, ANOMALY_DETAILS
from helpers import get_geoip_details

def register_callbacks(app):
    @app.callback(
        [Output('traffic-chart', 'figure'),
         Output('anomaly-table', 'data'), Output('anomaly-table', 'columns'),
         Output('live-stats-panel', 'children'),
         Output('network-topology-graph', 'elements')],
        [Input('interval-component', 'n_intervals'),
         Input('time-range-dropdown', 'value')]
    )
    def update_dashboard(n, time_range):
        analyze_live_traffic()
        
        traffic_query = f'from(bucket: "{INFLUX_BUCKET}") |> range(start: {time_range}) |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")'
        traffic_query_result = query_api.query_data_frame(org=INFLUX_ORG, query=traffic_query)

        anomaly_query = f'''
            from(bucket: "{INFLUX_BUCKET}") |> range(start: -24h) 
            |> filter(fn: (r) => r["_measurement"] == "detected_anomaly")
            |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
        '''
        hist_anomalies_result = query_api.query_data_frame(org=INFLUX_ORG, query=anomaly_query)
        
        hist_anomalies_df = pd.DataFrame()
        if isinstance(hist_anomalies_result, list) and hist_anomalies_result: hist_anomalies_df = pd.concat(hist_anomalies_result)
        elif isinstance(hist_anomalies_result, pd.DataFrame): hist_anomalies_df = hist_anomalies_result

        if not hist_anomalies_df.empty:
            hist_anomalies_df = hist_anomalies_df.rename(columns={'_time': 'timestamp'})
            hist_anomalies_df['timestamp'] = pd.to_datetime(hist_anomalies_df['timestamp'])
            hist_anomalies_df['timestamp_str'] = hist_anomalies_df['timestamp'].dt.strftime('%H:%M:%S')
            hist_anomalies_df = hist_anomalies_df.drop(columns=['result', 'table', '_start', 'stop', '_measurement'], errors='ignore')

        session_anomalies_df = pd.DataFrame(list(ANOMALY_DETAILS))
        if not session_anomalies_df.empty:
            session_anomalies_df['timestamp'] = pd.to_datetime(session_anomalies_df['timestamp'], unit='s').dt.tz_localize('UTC')
        
        if not hist_anomalies_df.empty:
            all_anomalies_df = pd.concat([session_anomalies_df, hist_anomalies_df]).drop_duplicates(subset=['timestamp_str', 'src_ip', 'dst_ip'], keep='first')
        else:
            all_anomalies_df = session_anomalies_df

        anomaly_records = all_anomalies_df.to_dict('records') if not all_anomalies_df.empty else []

        fig = go.Figure(layout={"template": "plotly_dark", "paper_bgcolor": "rgba(0,0,0,0)", "plot_bgcolor": "rgba(0,0,0,0)"})
        df_hist = pd.DataFrame()
        if isinstance(traffic_query_result, list) and traffic_query_result: df_hist = pd.concat(traffic_query_result)
        elif isinstance(traffic_query_result, pd.DataFrame): df_hist = traffic_query_result

        total_packets = len(df_hist)
        if not df_hist.empty:
            fig.add_trace(go.Scatter(x=df_hist['_time'], y=df_hist['packet_size'], mode='lines', name='Traffic', line=dict(color='#00BFFF')))
        
        graph_elements, nodes = [], set()
        if anomaly_records:
            df_anomalies = pd.DataFrame(anomaly_records)
            df_anomalies['timestamp'] = pd.to_datetime(df_anomalies['timestamp'])
            
            time_delta_str = time_range.replace('-', '').replace('m', 'T').replace('h', 'H')
            time_filter_start = pd.Timestamp.now(tz='UTC') - pd.Timedelta(time_delta_str)
            anomalies_for_graph = df_anomalies[df_anomalies['timestamp'] >= time_filter_start]

            if not anomalies_for_graph.empty:
                fig.add_trace(go.Scatter(x=anomalies_for_graph['timestamp'], y=anomalies_for_graph['packet_size'],
                                         mode='markers', name='Anomaly', marker=dict(color='#FF4136', size=10, symbol='x')))

            latest_anomalies_for_graph = anomaly_records[:30]
            for record in latest_anomalies_for_graph:
                src, dst = record['src_ip'], record['dst_ip']
                if src not in nodes: nodes.add(src); graph_elements.append({'data': {'id': src, 'label': src}})
                if dst not in nodes: nodes.add(dst); graph_elements.append({'data': {'id': dst, 'label': dst}})
                graph_elements.append({'data': {'source': src, 'target': dst}})

        required_cols = ['timestamp_str', 'src_ip', 'dst_ip', 'packet_size', 'reconstruction_error', 'threat_score']
        for col in required_cols:
            if col not in df_anomalies.columns: df_anomalies[col] = 'N/A'
        table_data = df_anomalies[required_cols].to_dict('records')

        table_columns = [{"name": i.replace("_", " ").title(), "id": i} for i in table_data[0].keys()] if table_data else []
        stats_children = [html.P(f"Total Anomalies Found: {len(anomaly_records)}")]

        fig.update_layout(title_text=f'Network Traffic for the {time_range.replace("-", "Last ")}',
                          xaxis_title_text="Time", yaxis_title_text="Packet Size (bytes)")
        

        table_data = []
        if anomaly_records:
            df_anomalies['Details'] = "<button>Details</button>"
            required_cols = ['timestamp_str', 'src_ip', 'dst_ip', 'packet_size', 'reconstruction_error', 'threat_score', 'Details']
            for col in required_cols:
                if col not in df_anomalies.columns:
                    df_anomalies[col] = 'N/A'
            table_df = df_anomalies[required_cols]
            table_data = table_df.to_dict('records')
        table_columns = [{"name": i.replace("_", " ").title(), "id": i, "presentation": "markdown"} for i in table_data[0].keys()] if table_data else []

        stats_children = [
            html.P(f"Packets in View: {total_packets}"),
            html.P(f"Total Anomalies Found: {len(anomaly_records)}")
        ]
        
        return fig, table_data, table_columns, stats_children, graph_elements

    @app.callback(
        [Output("details-modal", "is_open"), Output("modal-body-content", "children")],
        [Input("anomaly-table", "active_cell")],
        [State("anomaly-table", "data")]
    )
    def open_modal(active_cell, table_data):
        if not active_cell or not table_data or active_cell['column_id'] != 'Details': return False, None
        
        row_data = table_data[active_cell['row']]
        
        all_records = list(ANOMALY_DETAILS)
        full_record = next((r for r in all_records if r.get('timestamp_str') == row_data.get('timestamp_str') and r.get('src_ip') == row_data.get('src_ip')), row_data)
        
        if not full_record: return False, None
        
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

    @app.callback(
        Output("details-modal", "is_open", allow_duplicate=True),
        [Input("modal-close-button", "n_clicks")],
        [State("details-modal", "is_open")],
        prevent_initial_call=True
    )
    def close_modal(n, is_open):
        if n: return not is_open
        return is_open