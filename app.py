# app.py
from dash import Dash
import dash_bootstrap_components as dbc
from threading import Thread

from layout import layout
from callbacks import register_callbacks
from core_logic import start_sniffing

# Initialize the Dash app
app = Dash(__name__, suppress_callback_exceptions=True, external_stylesheets=[dbc.themes.DARKLY])
server = app.server

# Set the layout and register callbacks
app.layout = layout
register_callbacks(app)

# --- Main Execution ---
if __name__ == '__main__':
    # Start the packet sniffer in a background thread
    sniffer_thread = Thread(target=start_sniffing, daemon=True)
    print("Starting packet sniffer...")
    sniffer_thread.start()
    
    # Run the Dash server
    print("Starting Dash server...")
    app.run(debug=True, use_reloader=False)