from datetime import datetime, timezone
from pymongo import MongoClient
from bson import ObjectId
from config import Config  

client = MongoClient(Config.MONGODB_URI)
db = client['auth_db']

class User:
    collection = db['users']

    @staticmethod
    def create(username, password_hash, email, mfa_secret):
        user = {
            'username': username,
            'password': password_hash,
            'email': email,
            'mfa_secret': mfa_secret,
            'mfa_verified': False,
            'is_admin': False,
			'is_active': False,
            'failed_attempts': 0,
            'last_failed_attempt': None,
            'last_failed_ip': None,        
            'last_failed_location': None,   
            'created_at': datetime.now(timezone.utc),
            'last_login': None
        }
        result = User.collection.insert_one(user)
        return str(result.inserted_id)

    @staticmethod
    def get_by_username(username):
        return User.collection.find_one({'username': username})

    @staticmethod
    def get_by_email(email):
        return User.collection.find_one({'email': email})

    @staticmethod
    def update_mfa_verified(user_id, verified):
        User.collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'mfa_verified': verified}}
        )

    @staticmethod
    def update_password(user_id, password_hash):
        User.collection.update_one(
            {'_id': ObjectId(user_id)},
            {
                '$set': {
                    'password': password_hash,
                    'failed_attempts': 0,
                    'last_failed_attempt': None
                }
            }
        )

    @staticmethod
    def get_by_id(user_id):
        try:
            return User.collection.find_one({'_id': ObjectId(user_id)})
        except Exception as e:
            print(f"Error getting user by ID: {e}")
            return None

    @staticmethod
    def update_last_failed_attempt(user_id, ip_address=None, location=None):
        update_fields = {
            'last_failed_attempt': datetime.now(timezone.utc)
        }

        if ip_address is not None:
            update_fields['last_failed_ip'] = ip_address
        if location is not None:
            update_fields['last_failed_location'] = location

        User.collection.update_one(
            {'_id': ObjectId(user_id)},
            {
                '$set': update_fields,
                '$inc': {
                    'failed_attempts': 1
                }
            }
        )

    @staticmethod
    def update_last_login(user_id):
        User.collection.update_one(
            {'_id': ObjectId(user_id)},
            {
                '$set': {
                    'last_login': datetime.now(timezone.utc),
                    'failed_attempts': 0,
                    'last_failed_attempt': None,
                    'is_active': True
                }
            }
        )
    
    @staticmethod
    def update_logout(user_id):
        User.collection.update_one(
            {'_id': ObjectId(user_id)},
            {'$set': {'is_active': False}}
        )
    
    @staticmethod
    def verify_admin_status(user_id):
        """Securely verify if a user has admin privileges"""
        try:
            user = User.collection.find_one(
                {'_id': ObjectId(user_id)},
                {'is_admin': 1}  # Only retrieve the is_admin field
            )
            return bool(user.get('is_admin', False)) if user else False
        except Exception as e:
            print(f"Error verifying admin status: {e}")
            return False

class Session:
    collection = db['sessions']

    @staticmethod
    def create(user_id, token, ip_address, user_agent):
        session = {
            'user_id': ObjectId(user_id),
            'token': token,
            'ip_address': ip_address,
            'user_agent': user_agent,
            'created_at': datetime.now(timezone.utc),
            'last_activity': datetime.now(timezone.utc)
        }
        Session.collection.insert_one(session)

    @staticmethod
    def invalidate(token):
        Session.collection.delete_one({'token': token})