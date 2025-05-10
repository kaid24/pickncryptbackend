from datetime import datetime, timedelta, timezone
from logging.handlers import TimedRotatingFileHandler
import os
import sys
from threading import Thread
import time

from bson import ObjectId
import requests
from extensions import socketio
from flask import Blueprint, request, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room, rooms
from flask_jwt_extended import (
    create_access_token, create_refresh_token, decode_token, get_jwt,
    jwt_required, get_jwt_identity, verify_jwt_in_request
)
from models import User, Session
from auth import (
    hash_password, verify_password,
    generate_mfa_secret, verify_mfa_code,
    require_mfa
)
from email_validator import validate_email, EmailNotValidError
import re
import logging
import json
from functools import wraps

# Custom formatter class definition
class CustomFormatter(logging.Formatter):
    grey = "\x1b[38;21m"
    blue = "\x1b[34;21m"
    yellow = "\x1b[33;21m"
    red = "\x1b[31;21m"
    bold_red = "\x1b[31;1m"
    reset = "\x1b[0m"

    SYMBOLS = {
        'success': '[+]',
        'error': '[x]',
        'entry': '>>',
        'exit': '<<',
        'warning': '[!]',
        'info': '[*]'
    }

    format_str = "%(asctime)s - %(levelname)s - %(message)s"

    FORMATS = {
        logging.DEBUG: blue + format_str + reset,
        logging.INFO: grey + format_str + reset,
        logging.WARNING: yellow + format_str + reset,
        logging.ERROR: red + format_str + reset,
        logging.CRITICAL: bold_red + format_str + reset
    }

    def format(self, record):
        log_fmt = self.FORMATS.get(record.levelno)
        formatter = logging.Formatter(log_fmt, datefmt='%Y-%m-%d %H:%M:%S')
        return formatter.format(record)

def setup_logger():
    # Get or create logger
    logger = logging.getLogger('PickNCrypt')
    
    # Clear any existing handlers
    if logger.hasHandlers():
        logger.handlers.clear()
    
    logger.setLevel(logging.DEBUG)
    logger.propagate = False  # Prevent propagation to root logger

    # Create logs directory if it doesn't exist
    logs_dir = 'logs'
    if not os.path.exists(logs_dir):
        os.makedirs(logs_dir)

    # Log file base name with current date
    current_date = datetime.now().strftime("%Y-%m-%d")
    log_base_filename = os.path.join(logs_dir, f'pickncrypt_{current_date}.log')

    # Create console handler
    if sys.platform.startswith('win'):
        sys.stdout.reconfigure(encoding='utf-8')
        ch = logging.StreamHandler(sys.stdout)
    else:
        ch = logging.StreamHandler()
    ch.setLevel(logging.DEBUG)

    # Create timed rotating file handler
    fh = TimedRotatingFileHandler(
        filename=log_base_filename,
        when='W0',  # Weekly rotation on Monday
        interval=1,  # Every week
        backupCount=7,  # Keep 7 weeks of logs
        encoding='utf-8',
        delay=True  # Delay creation of file until first log message
    )
    fh.setLevel(logging.DEBUG)

    # Plain formatter for file output
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    # Set formatters
    ch.setFormatter(CustomFormatter())
    fh.setFormatter(file_formatter)

    # Add handlers to logger
    logger.addHandler(ch)
    logger.addHandler(fh)

    return logger

# Initialize logger
logger = setup_logger()

api = Blueprint('api', __name__)

# Global state
waiting_users = {}  # user_id -> socket_id
active_chat_rooms = {}  # room_id -> {users: [], messages: []}
connected_users = {}  # user_id -> {sid: socket_id, room_id: current_room, username: str}
room_members = {}    # room_id -> set of user_ids
user_sessions = {}   # sid -> user_id

def get_username_from_id(user_id):
    """Helper function to get username from user ID"""
    try:
        user = User.get_by_id(user_id)
        return user['username'] if user else f"Unknown User ({user_id})"
    except Exception as e:
        logger.error(f"Error getting username for ID {user_id}: {str(e)}")
        return f"Unknown User ({user_id})"
    
# Decorator for logging function entry/exit
def log_function(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        func_name = func.__name__
        logger.debug(f"{CustomFormatter.SYMBOLS['entry']} Entering {func_name}")
        try:
            result = func(*args, **kwargs)
            logger.debug(f"{CustomFormatter.SYMBOLS['exit']} Exiting {func_name}")
            return result
        except Exception as e:
            logger.error(f"{CustomFormatter.SYMBOLS['error']} Error in {func_name}: {str(e)}")
            raise
    return wrapper
    
def get_location_from_ip(ip_address):
    try:
        response = requests.get(f'https://ipapi.co/{ip_address}/json/')
        if response.status_code == 200:
            data = response.json()
            location = {
                'city': data.get('city'),
                'region': data.get('region'),
                'country': data.get('country_name'),
                'latitude': data.get('latitude'),
                'longitude': data.get('longitude'),
            }
            return location
        else:
            print(f"Failed to obtain location data for IP {ip_address}")
            return None
    except Exception as e:
        print(f"Error obtaining location for IP {ip_address}: {e}")
        return None

@api.route('/register', methods=['POST'])
@log_function
def register():
    data = request.get_json()
    logger.info(f"Registration attempt for username: '{data.get('username')}'")
    
    # Validate input
    if not all(k in data for k in ['username', 'password', 'email']):
        return jsonify({'error': 'Missing required fields'}), 400

    # Validate username
    if len(data['username']) < 4:
        return jsonify({'error': 'Username must be at least 4 characters'}), 400

    # Validate password
    if not re.match(r'^(?=.*[A-Za-z])(?=.*\d).{8,}$', data['password']):
        return jsonify({'error': 'Invalid password format'}), 400

    # Validate email
    try:
        validate_email(data['email'])
    except EmailNotValidError:
        return jsonify({'error': 'Invalid email'}), 400

    # Check if user exists
    if User.get_by_username(data['username']):
        return jsonify({'error': 'Username already exists'}), 409

    # Generate MFA secret
    mfa_secret = generate_mfa_secret()

    # Create user
    user_id = User.create(
        username=data['username'],
        password_hash=hash_password(data['password']),
        email=data['email'],
        mfa_secret=mfa_secret
    )
    
    logger.info(f"Registration successful for user: '{data['username']}'")
    return jsonify({
        'message': 'Registration successful',
        'mfa_secret': mfa_secret,
        'user_id': user_id
    }), 201

@api.route('/verify-credentials', methods=['POST'])
@log_function
def verify_credentials():
    data = request.get_json()
    logger.info(f"Login attempt for username: '{data.get('username')}'")
    
    if not all(k in data for k in ['username', 'password']):
        return jsonify({'error': 'Missing required fields'}), 400

    user = User.get_by_username(data['username'])
    if not user:
        return jsonify({'error': 'User not found'}), 401
    
    # Extract the IP address from the request
    ip_address = request.remote_addr
    location = get_location_from_ip(ip_address)

    if not verify_password(data['password'], user['password']):
        # Log failed attempt
        User.update_last_failed_attempt(
            user_id=user['_id'],
            ip_address=ip_address,
            location=location
        )
        logger.warning(f"Failed login attempt for user '{user['username']}' from IP {ip_address} - {location}")
        return jsonify({'error': 'Invalid credentials'}), 401

    logger.info(f"Login successful for user: '{user['username']}'")
    return jsonify({
        'message': 'Credentials verified',
        'user_id': str(user['_id']),
        'requires_mfa': True
    }), 200

@api.route('/verify-mfa', methods=['POST'])
@log_function
def verify_login_mfa():
    data = request.get_json()
    user_id = data.get('user_id')
    username = get_username_from_id(user_id)
    logger.info(f"MFA verification attempt for username: '{username}'")
    
    if not all(k in data for k in ['user_id', 'mfa_code']):
        logger.warning("Missing required fields in MFA verification")
        return jsonify({'error': 'Missing required fields'}), 400

    user = User.get_by_id(data['user_id'])
    if not user:
        logger.warning(f"User not found for MFA verification: '{username}'")
        return jsonify({'error': 'User not found'}), 404

    if not verify_mfa_code(user['mfa_secret'], data['mfa_code']):
        User.update_last_failed_attempt(str(user['_id']))
        logger.warning(f"Invalid MFA code for user: '{username}'")
        return jsonify({'error': 'Invalid MFA code'}), 401
    
    User.update_last_login(str(user['_id']))

    # Generate tokens
    access_token = create_access_token(identity=str(user['_id']))
    refresh_token = create_refresh_token(identity=str(user['_id']))

    # Check admin status
    is_admin = User.verify_admin_status(str(user['_id']))
    logger.info(f"User '{username}' admin status: {is_admin}")

    return jsonify({
        'message': 'Login successful',
        'access_token': access_token,
        'refresh_token': refresh_token,
        'is_admin': is_admin
    }), 200

@api.route('/verify-admin', methods=['GET'])
@jwt_required()
@log_function
def verify_admin():
    try:
        current_user_id = get_jwt_identity()
        username = get_username_from_id(current_user_id)
        
        # Get full user details
        user = User.get_by_id(current_user_id)
        if not user:
            logger.warning(f"User not found: {username}")
            return jsonify({'is_admin': False}), 404
            
        is_admin = user.get('is_admin', False)
        
        return jsonify({
            'is_admin': is_admin,
            'username': username
        }), 200
        
    except Exception as e:
        logger.error(f"Admin verification error: {str(e)}")
        return jsonify({'error': 'Verification failed'}), 500

@api.route('/admin/users', methods=['GET'])
@jwt_required()
@log_function
def get_admin_users():
    try:
        # Verify admin status
        current_user_id = get_jwt_identity()
        username = get_username_from_id(current_user_id)
        if not User.verify_admin_status(current_user_id):
            logger.warning(f"Unauthorized admin access attempt by user ID: {current_user_id}")
            return jsonify({'error': 'Unauthorized access'}), 403

        # Fetch all users
        users = list(User.collection.find({}, {
            'password': 0,
            'mfa_secret': 0
        }))
        
        # Convert ObjectId to string for JSON serialization
        for user in users:
            user['_id'] = str(user['_id'])
            # Convert datetime objects to strings
            for key in ['created_at', 'last_login', 'last_failed_attempt']:
                if key in user and user[key]:
                    user[key] = user[key].isoformat()

        logger.info(f"Admin user list retrieved by user ID: {username}")
        return jsonify({'users': users}), 200

    except Exception as e:
        logger.error(f"Error in admin users retrieval: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@api.route('/admin/users/<user_id>', methods=['GET'])
@jwt_required()
@log_function
def get_admin_user_details(user_id):
    try:
        # Verify admin status
        current_user_id = get_jwt_identity()
        username = get_username_from_id(current_user_id)
        if not User.verify_admin_status(current_user_id):
            logger.warning(f"Unauthorized admin access attempt by user ID: {username}")
            return jsonify({'error': 'Unauthorized access'}), 403

        # Fetch user details
        user = User.collection.find_one(
            {'_id': ObjectId(user_id)},
            {'password': 0, 'mfa_secret': 0}
        )

        if not user:
            return jsonify({'error': 'User not found'}), 404

        # Convert ObjectId to string
        user['_id'] = str(user['_id'])
        # Convert datetime objects to strings
        for key in ['created_at', 'last_login', 'last_failed_attempt']:
            if key in user and user[key]:
                user[key] = user[key].isoformat()

        logger.info(f"Admin user details retrieved for user ID: {user_id}")
        return jsonify({'user': user}), 200

    except Exception as e:
        logger.error(f"Error in admin user details retrieval: {str(e)}")
        return jsonify({'error': 'Internal server error'}), 500

@socketio.on('connect')
@log_function
def handle_connect(*args):
    try:
        auth_header = request.headers.get('Authorization')
        if not auth_header or not auth_header.startswith('Bearer '):
            logger.warning("Socket connection attempt without authentication")
            raise ConnectionRefusedError('Authentication required')
            
        token = auth_header.split(' ')[1]
        user_id = verify_jwt_token(token)
        username = get_username_from_id(user_id)
        
        # Store the mapping of socket ID to user ID
        user_sessions[request.sid] = user_id
        
        # Update or create user connection info
        if user_id in connected_users:
            old_sid = connected_users[user_id]['sid']
            if old_sid != request.sid:
                if old_sid in user_sessions:
                    del user_sessions[old_sid]
                logger.info(f"Updating connection for user '{username}'")
        
        connected_users[user_id] = {
            'sid': request.sid,
            'room_id': None,
            'username': username
        }
        
        logger.info(f"User '{username}' connected with socket {request.sid}")
        return True
    except Exception as e:
        logger.error(f"Socket connection error: {str(e)}")
        raise ConnectionRefusedError('Authentication failed')

@socketio.on('disconnect')
@log_function
def handle_disconnect():
    try:
        sid = request.sid
        user_id = user_sessions.get(sid)
        
        if user_id and user_id in connected_users:
            # Only disconnect if this is the current session
            if connected_users[user_id]['sid'] == sid:
                username = connected_users[user_id]['username']
                room_id = connected_users[user_id]['room_id']
                
                # Remove from room if in one
                if room_id and room_id in room_members:
                    room_members[room_id].discard(user_id)
                    if not room_members[room_id]:
                        del room_members[room_id]
                
                # Remove from waiting users if present
                if user_id in waiting_users:
                    del waiting_users[user_id]
                
                # Remove connection data
                del connected_users[user_id]
                logger.info(f"User '{username}' disconnected")
        
        # Clean up session mapping
        if sid in user_sessions:
            del user_sessions[sid]
            
    except Exception as e:
        logger.error(f"Error in disconnect handler: {str(e)}")

@socketio.on('start_matchmaking')
@jwt_required()
@log_function
def handle_matchmaking(data=None):
    user_id = get_jwt_identity()
    username = get_username_from_id(user_id)
    logger.info(f"Starting matchmaking for user '{username}'")

    # Check if user is already in a chat room
    current_rooms = rooms()
    for room_id, room_data in active_chat_rooms.items():
        if user_id in room_data['users']:
            if room_id not in current_rooms:  # Only join if not already in room
                join_room(room_id)
                logger.info(f"User '{username}' rejoined existing room {room_id}")
                emit('match_found', {
                    'room_id': room_id,
                    'users': room_data['users']
                })
            return

    # Look for waiting users
    for waiting_id, socket_id in waiting_users.items():
        if waiting_id != user_id:
            room_id = f"room_{waiting_id}_{user_id}"
            active_chat_rooms[room_id] = {
                'users': [waiting_id, user_id],
                'messages': []
            }
            logger.info(f"Created new room: {room_id}")

            # Join both users to the room
            join_room(room_id)
            
            # Emit to both users
            match_data = {
                'room_id': room_id,
                'users': [waiting_id, user_id]
            }
            
            # Notify both users
            if socket_id:
                socketio.emit('match_found', match_data, to=socket_id)
            emit('match_found', match_data)

            wait_username = get_username_from_id(waiting_id)
            logger.info(f"Match created between users '{username}' and '{wait_username}'")
            del waiting_users[waiting_id]
            return

    # No match found, add to waiting pool
    waiting_users[user_id] = request.sid
    logger.info(f"User '{username}' added to waiting pool")
    emit('waiting_for_match')

@socketio.on('join_room')
@log_function
def on_join(data):
    try:
        sid = request.sid
        user_id = user_sessions.get(sid)
        
        if not user_id or user_id not in connected_users:
            logger.warning(f"Join attempt from unconnected session: {sid}")
            emit('error', {'message': 'Not connected'})
            return
            
        room_id = data.get('room_id')
        username = connected_users[user_id]['username']
        public_key_b64 = data.get('public_key')

        if not room_id:
            logger.warning("Room join attempt without room ID")
            emit('error', {'message': 'Room ID required'})
            return
        
        # Save user's public key
        if public_key_b64:
            connected_users[user_id]['public_key'] = public_key_b64
        
        # Check if user is already in this room
        if connected_users[user_id]['room_id'] == room_id:
            logger.debug(f"User '{username}' already in room {room_id}")
            emit('room_joined', {'room_id': room_id})
            return
            
        # Check if room exists and user is authorized
        if room_id in active_chat_rooms and user_id in active_chat_rooms[room_id]['users']:
            # Update room tracking
            if room_id not in room_members:
                room_members[room_id] = set()
            room_members[room_id].add(user_id)
            
            # Update user's current room
            connected_users[user_id]['room_id'] = room_id
            
            # Join socket.io room
            join_room(room_id)
            
            logger.info(f"User '{username}' joined room {room_id}")

            room_users = active_chat_rooms[room_id]['users']
            peer_id = next((uid for uid in room_users if uid != user_id), None)
            peer_public_key = connected_users.get(peer_id, {}).get('public_key')
            own_public_key = connected_users[user_id].get('public_key')

            # If both users have public keys, send each other's keys
            if peer_id and peer_public_key and own_public_key:
                logger.info(f"Both users in room {room_id} have keys. Sending peer keys.")

                # Send peer key to this user
                emit('room_joined', {
                    'room_id': room_id,
                    'peer_public_key': peer_public_key
                }, to=sid)

                # Send this user's key to the peer
                peer_sid = connected_users[peer_id]['sid']
                emit('room_joined', {
                    'room_id': room_id,
                    'peer_public_key': own_public_key
                }, to=peer_sid)
            else:
                logger.info(f"Only one user in room {room_id}. Waiting for both public keys.")

        else:
            logger.warning(f"Invalid room join attempt: {room_id} by user '{username}'")
            emit('error', {'message': 'Invalid room or not authorized'})
            
    except Exception as e:
        logger.error(f"Error joining room: {str(e)}")
        emit('error', {'message': 'Failed to join room'})

@socketio.on('leave_chat')
@jwt_required()
@log_function
def handle_leave_chat(data=None): 
    user_id = get_jwt_identity()
    username = get_username_from_id(user_id)
    logger.info(f"User '{username}' attempting to leave chat")
    
    room_id = data.get('room_id') if data else None
    if room_id and room_id in active_chat_rooms:
        if user_id in active_chat_rooms[room_id]['users']:
            # Notify other user before removing from room
            other_user = next(
                (uid for uid in active_chat_rooms[room_id]['users'] if uid != user_id),
                None
            )
            
            # Remove user from room
            active_chat_rooms[room_id]['users'].remove(user_id)
            leave_room(room_id)
            logger.info(f"User '{username}' left room {room_id}")
            
            # Notify other user and close room
            if other_user:
                other_username = get_username_from_id(other_user)
                emit('chat_ended', {
                    'message': f'{username} has left the conversation',
                    'user_id': user_id,
                    'room_closed': True
                }, room=room_id)
                logger.info(f"Notified user '{other_username}' about partner leaving")
            
            # Clean up room
            del active_chat_rooms[room_id]
            logger.info(f"Room {room_id} closed")

@socketio.on('send_message')
@log_function
def handle_message(data):
    """
    Handles receiving and broadcasting encrypted messages in a chatroom.
    """
    try:
        auth = data.get('authorization', '')
        if not auth or not auth.startswith('Bearer '):
            logger.warning("Message attempt without authentication")
            emit('error', {'message': 'Authentication required'})
            return

        token = auth.split(' ')[1]
        try:
            decoded = decode_token(token)
            user_id = decoded['sub']
        except Exception as e:
            logger.error(f"Invalid token in message: {str(e)}")
            emit('error', {'message': 'Invalid token'})
            return

        room_id = data.get('room_id')
        encrypted_message = data.get('message')
        username = get_username_from_id(user_id)

        logger.info(f"Message received from '{username}' in room {room_id}")

        if not room_id:
            logger.warning("Missing room ID")
            emit('error', {'message': 'Missing room ID'})
            return
        
        if not encrypted_message:
            logger.warning("Missing message content")
            emit('error', {'message': 'Missing message'})
            return

        if room_id not in active_chat_rooms:
            logger.warning(f"Room not found: {room_id}")
            emit('error', {'message': 'Chat room not found'})
            return

        if user_id not in active_chat_rooms[room_id]['users']:
            logger.warning(f"User '{username}' not authorized for room {room_id}")
            emit('error', {'message': 'Not in chat room'})
            return

        message = {
            'message': encrypted_message,
            'sender': get_username_from_id(user_id)
        }

        logger.debug(f"Message details: {json.dumps(message, indent=2)}")

        # Store encrypted message
        active_chat_rooms[room_id]['messages'].append(message)

        # Broadcast encrypted message to room
        socketio.emit('new_message', {
            'message': encrypted_message,
            'sender': user_id
        }, room=room_id)

        logger.info(f"Encrypted message successfully broadcast to room {room_id}")

    except Exception as e:
        logger.error(f"Error handling message: {str(e)}")
        emit('error', {'message': f'Failed to send message: {str(e)}'})

def verify_jwt_token(token):
    try:
        decoded = decode_token(token)
        user_id = decoded['sub']
        username = get_username_from_id(user_id)
        logger.debug(f"Token verified for user '{username}'")
        return decoded['sub']
    except Exception as e:
        logger.error(f"Token verification error: {str(e)}")
        raise

# Cleanup function for old logs
def cleanup_old_logs():
    try:
        current_time = datetime.now()
        retention_days = 7

        for filename in os.listdir('logs'):
            filepath = os.path.join('logs', filename)
            
            if not os.path.isfile(filepath):
                continue
                
            file_time = datetime.fromtimestamp(os.path.getmtime(filepath))
            
            if current_time - file_time > timedelta(days=retention_days):
                try:
                    os.remove(filepath)
                    logger.debug(f"{CustomFormatter.SYMBOLS['info']} Deleted old log file: {filename}")
                except Exception as e:
                    logger.error(f"{CustomFormatter.SYMBOLS['error']} Error deleting {filename}: {str(e)}")

    except Exception as e:
        logger.error(f"{CustomFormatter.SYMBOLS['error']} Error during log cleanup: {str(e)}")

def periodic_cleanup():
    while True:
        cleanup_old_logs()
        time.sleep(86400)  # Sleep for 24 hours

# Start the cleanup thread
cleanup_thread = Thread(target=periodic_cleanup, daemon=True)
cleanup_thread.start()

# Run initial cleanup
cleanup_old_logs()

@api.route('/login', methods=['POST'])
@log_function
def login():
    data = request.get_json()
    logger.info(f"Full login attempt for username: '{data.get('username')}'")
    
    if not all(k in data for k in ['username', 'password', 'mfa_code']):
        logger.warning("Missing required fields in login")
        return jsonify({'error': 'Missing required fields'}), 400

    user = User.get_by_username(data['username'])
    if not user:
        logger.warning(f"Invalid credentials for username: '{data.get('username')}'")
        return jsonify({'error': 'Invalid credentials'}), 401

    if not verify_password(data['password'], user['password']):
        User.update_last_failed_attempt(str(user['_id']))
        logger.warning(f"Invalid password for username: '{data.get('username')}'")
        return jsonify({'error': 'Invalid credentials'}), 401

    if not user['mfa_verified']:
        logger.warning(f"MFA not verified for username: '{data.get('username')}'")
        return jsonify({'error': 'MFA not verified'}), 401

    if not verify_mfa_code(user['mfa_secret'], data['mfa_code']):
        User.update_last_failed_attempt(str(user['_id']))
        logger.warning(f"Invalid MFA code for username: '{data.get('username')}'")
        return jsonify({'error': 'Invalid MFA code'}), 401

    # Update last login time
    User.update_last_login(str(user['_id']))

    access_token = create_access_token(
        identity=str(user['_id']),
        additional_claims={'mfa_verified': True}
    )
    refresh_token = create_refresh_token(identity=str(user['_id']))

    Session.create(
        user_id=str(user['_id']),
        token=access_token,
        ip_address=request.remote_addr,
        user_agent=request.user_agent.string
    )

    logger.info(f"Full login successful for user: {data.get('username')}")
    return jsonify({
        'access_token': access_token,
        'refresh_token': refresh_token
    }), 200

@api.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
@log_function
def refresh():
    identity = get_jwt_identity()
    username = get_username_from_id(identity)
    logger.info(f"Token refresh request for user: '{username}'")
    access_token = create_access_token(identity=identity)
    logger.info(f"Token refreshed for user: '{username}'")
    return jsonify({'access_token': access_token}), 200

@api.route('/logout', methods=['POST'])
@jwt_required()
@log_function
def logout():
    token = request.headers.get('Authorization').split()[1]
    user_id = get_jwt_identity()
    username = get_username_from_id(user_id)
    logger.info(f"Logout request for user: '{username}'")
    
    # Invalidate the session token
    Session.invalidate(token)
    
    # Update the user's 'is_active' status to False
    User.update_logout(user_id)
    
    logger.info(f"Logout successful for user: '{username}'")
    return jsonify({'message': 'Logged out successfully'}), 200

@api.route('/reset-password', methods=['POST'])
@jwt_required()
@log_function
def reset_password():
    data = request.get_json()
    logger.info(f"Password reset attempt for email: {data.get('email')}")
    
    if not all(k in data for k in ['email', 'mfa_code', 'new_password']):
        return jsonify({'error': 'Missing required fields'}), 400

    user = User.get_by_email(data['email'])
    if not user:
        return jsonify({'error': 'Email not found'}), 404

    if not verify_mfa_code(user['mfa_secret'], data['mfa_code']):
        return jsonify({'error': 'Invalid MFA code'}), 401

    if not re.match(r'^(?=.*[A-Za-z])(?=.*\d).{8,}$', data['new_password']):
        return jsonify({'error': 'Invalid password format'}), 400

    User.update_password(
        str(user['_id']),
        hash_password(data['new_password'])
    )

    return jsonify({'message': 'Password reset successful'}), 200

# Error handlers
@api.errorhandler(Exception)
def handle_error(error):
    logger.error(f"Unhandled error: {str(error)}")
    return jsonify({'error': 'Internal server error'}), 500

@api.errorhandler(404)
def not_found(error):
    logger.warning(f"Route not found: {request.url}")
    return jsonify({'error': 'Not found'}), 404
