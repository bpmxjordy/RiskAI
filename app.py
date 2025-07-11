# app.py
import dash
import dash_bootstrap_components as dbc
from dash import html
from threading import Thread
from core_logic import start_sniffing

# Initialize the Dash app, enabling the pages router
app = dash.Dash(__name__, use_pages=True, external_stylesheets=[dbc.themes.DARKLY])
server = app.server

# Define the navigation bar
navbar = dbc.NavbarSimple(
    children=[
        dbc.NavItem(dbc.NavLink("Live Dashboard", href="/")),
        dbc.NavItem(dbc.NavLink("Anomalies History", href="/history")),
    ],
    brand="AI Network Security Monitor",
    brand_href="/",
    color="primary",
    dark=True,
    className="mb-4"
)

# Main app layout
app.layout = html.Div([
    navbar,
    # Content of each page will be rendered in this container
    dash.page_container
])

if __name__ == '__main__':
    # Start the packet sniffer in a background thread
    sniffer_thread = Thread(target=start_sniffing, daemon=True)
    print("Starting packet sniffer...")
    sniffer_thread.start()

    # Run the Dash server
    print("Starting Dash server...")
    app.run(debug=True, use_reloader=False)