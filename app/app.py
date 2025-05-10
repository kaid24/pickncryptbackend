# app.py
from config import Config
from extensions import app, socketio
from routes import api
from flask import Flask
from flask_socketio import SocketIO
import os

app = Flask(__name__)
app.config.from_object(Config)
app.register_blueprint(api, url_prefix='/api')


# Initialize SocketIO
socketio = SocketIO(app, cors_allowed_origins="*")  # Adjust CORS as needed

if __name__ == "__main__":
    socketio.run(app, host='0.0.0.0', port=int(os.environ.get('PORT', 8080)))
