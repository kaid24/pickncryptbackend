from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager
from flask_socketio import SocketIO

app = Flask(__name__)

ALLOWED_ORIGINS = [
        'https://pickncryptbackend-production.up.railway.app:8080',
        'https://pickncryptbackend-production.up.railway.app'
    ]

# Create a lowercase version for case-insensitive matching
ALLOWED_ORIGINS_LOWERCASE = [origin.lower() for origin in ALLOWED_ORIGINS]

# Case-insensitive origin validator
def case_insensitive_origin_validator(origin):
    if origin is None:
        return False
    
    # Convert to lowercase before comparison
    return origin.lower() in ALLOWED_ORIGINS_LOWERCASE

# Apply CORS with case-insensitive validation
CORS(app, resources={
    r"/*": {
        "origins": case_insensitive_origin_validator,
        "allow_headers": ["Authorization", "Content-Type"],
        "methods": ["GET", "POST", "OPTIONS"]
    }
})

jwt = JWTManager(app)
socketio = SocketIO(
    app, 
    cors_allowed_origins=ALLOWED_ORIGINS,
    logger=True,
    engineio_logger=True
)
