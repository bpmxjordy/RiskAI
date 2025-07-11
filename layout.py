# layout.py
from dash import dcc, html, dash_table
import dash_bootstrap_components as dbc
import dash_cytoscape as cyto

CONTENT_STYLE = {"marginLeft": "2rem", "marginRight": "2rem", "padding": "2rem 1rem"}
default_stylesheet = [
    {'selector': 'node', 'style': {'label': 'data(label)', 'color': 'white', 'background-color': '#0074D9'}},
    {'selector': 'edge', 'style': {'line-color': '#555', 'width': 2}},
    {'selector': '[id *= "192.168."]', 'style': {'background-color': '#FF851B', 'shape': 'star'}}
]

layout = html.Div([
    # --- THIS IS THE FIX ---
    # Add the missing dcc.Store component here
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