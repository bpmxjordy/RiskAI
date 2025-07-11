# pages/history.py
import dash
from dash import dcc, html, Input, Output
import dash_bootstrap_components as dbc
from core_logic import query_api, INFLUX_BUCKET, INFLUX_ORG
import pandas as pd

dash.register_page(__name__, path='/history')

layout = dbc.Container([
    dbc.Card(className="card-style", body=True, children=[
        html.H2("Anomaly History", className="text-center mb-4"),
        dbc.Row([
            dbc.Col(dcc.DatePickerRange(
                id='history-date-picker', display_format='YYYY-MM-DD', className="mb-2"
            ), width=12),
            dbc.Col(dbc.Input(id='history-ip-filter', placeholder='Filter by IP Address...'), md=6),
            dbc.Col(dbc.Input(id='history-country-filter', placeholder='Filter by Country...'), md=6),
        ], className="mb-4"),
        html.Div(id='history-table-container')
    ])
], fluid=True)

@dash.callback(
    Output('history-table-container', 'children'),
    [Input('history-date-picker', 'start_date'),
     Input('history-date-picker', 'end_date'),
     Input('history-ip-filter', 'value'),
     Input('history-country-filter', 'value')]
)
def update_history_table(start_date, end_date, ip_filter, country_filter):
    range_start = start_date if start_date else "-7d"
    range_stop_filter = f'|> filter(fn: (r) => r._time < {end_date}T23:59:59Z)' if end_date else ""
    
    query = f'''
        from(bucket: "{INFLUX_BUCKET}")
        |> range(start: {range_start})
        {range_stop_filter}
        |> filter(fn: (r) => r["_measurement"] == "detected_anomaly")
        |> pivot(rowKey:["_time"], columnKey: ["_field"], valueColumn: "_value")
        |> sort(columns: ["_time"], desc: true)
    '''
    df = query_api.query_data_frame(org=INFLUX_ORG, query=query)
    
    if isinstance(df, list):
        if not df: return html.P("No anomalies found for the selected criteria.")
        df = pd.concat(df)
        
    if df.empty:
        return html.P("No anomalies found for the selected criteria.")
        
    df = df.drop(columns=['result', 'table', '_start', 'stop', '_measurement'], errors='ignore')
    df['_time'] = pd.to_datetime(df['_time']).dt.strftime('%Y-%m-%d %H:%M:%S')

    if ip_filter:
        df = df[df['src_ip'].str.contains(ip_filter, na=False) | df['dst_ip'].str.contains(ip_filter, na=False)]
    if country_filter:
        df = df[df['country'].str.contains(country_filter, case=False, na=False)]

    if df.empty:
        return html.P("No anomalies match the current filters.")

    df = df.rename(columns={
        '_time': 'Timestamp', 'src_ip': 'Source IP', 'dst_ip': 'Destination IP', 
        'packet_size': 'Packet Size', 'reconstruction_error': 'Error Score', 
        'threat_score': 'Threat Score', 'country': 'Country'
    })

    table_header = [html.Thead(html.Tr([html.Th(col) for col in df.columns]))]
    table_body = [html.Tbody([
        html.Tr([html.Td(df.iloc[i][col]) for col in df.columns]) for i in range(len(df))
    ])]

    history_table = dbc.Table(table_header + table_body,
                              color="dark", striped=False, bordered=False, hover=True, 
                              responsive=True, className="table-shimmer")
                              
    return history_table