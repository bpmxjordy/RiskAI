# layout.py
from dash import dcc, html, dash_table
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto

modern_stylesheet = [
    {'selector': 'node', 'style': {'label': 'data(label)', 'color': '#fff', 'font-size': '14px'}},
    {'selector': 'edge', 'style': {'line-color': '#555', 'width': 2}},
    {'selector': '[id *= "192.168."]', 'style': {'background-color': '#FF851B', 'shape': 'star'}}
]

layout = html.Div([
    html.H1("AI Network Security Monitor", style={'textAlign': 'center', 'padding': '20px'}),
    dbc.Container([
        dbc.Row([
            dbc.Col([
                dbc.Card(dcc.Graph(id='traffic-chart'), className="card-style mb-4"),
                dbc.Card(dbc.CardBody([
                    html.H4("Detected Anomaly Details"),
                    html.Div(className="table-style", children=[
                        dash_table.DataTable(id='anomaly-table',
                            style_header={'backgroundColor': 'transparent', 'fontWeight': 'bold'},
                            style_cell={'backgroundColor': 'transparent', 'color': 'white', 'border': 'none'},
                            markdown_options={"html": True})
                    ])
                ]), className="card-style"),
            ], md=8),
            dbc.Col([
                dbc.Card(dbc.CardBody([
                    html.H4("Time Controls"),
                    dcc.Dropdown(id='time-range-dropdown',
                        options=[{'label': 'Last 5 Minutes', 'value': '-5m'}, {'label': 'Last Hour', 'value': '-1h'}],
                        value='-5m'),
                ]), className="card-style mb-4"),
                dbc.Card(dbc.CardBody([
                    html.H4("Live Stats"),
                    html.Div(id='live-stats-panel')
                ]), className="card-style mb-4"),
                dbc.Card(dbc.CardBody([
                    html.H4("Anomaly Connection Graph"),
                    cyto.Cytoscape(id='network-topology-graph', layout={'name': 'cose'},
                        stylesheet=modern_stylesheet,
                        style={'width': '100%', 'height': '350px'})
                ]), className="card-style"),
            ], md=4),
        ]),
    ], fluid=True),
    dcc.Interval(id='interval-component', interval=5*1000, n_intervals=0)
])