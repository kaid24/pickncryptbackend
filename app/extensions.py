from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_socketio import SocketIO

app = Flask(__name__)

CORS(app, resources={
    r"/*": {
        "origins": '*',
        "allow_headers": ["Authorization", "Content-Type"],
        "methods": ["GET", "POST", "OPTIONS"]
    }
})

jwt = JWTManager(app)
socketio = SocketIO(
    app, 
    cors_allowed_origins='*',
    logger=True,
    engineio_logger=True
)
