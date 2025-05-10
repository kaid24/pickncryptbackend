# app.py
from config import Config
from extensions import app, socketio
from routes import api

app.config.from_object(Config)
app.register_blueprint(api, url_prefix='/api')

if __name__ == '__main__':
    socketio.run(app, port=8080)