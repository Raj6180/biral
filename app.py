from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_migrate import Migrate
from dotenv import load_dotenv
import os

# Load environment variables from .env
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messaging.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

# Extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
socketio = SocketIO(app, cors_allowed_origins="*")
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# --------------------------- Models ---------------------------
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    online = db.Column(db.Boolean, default=False)

    def is_online(self):
        return self.online

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)

    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])

# --------------------------- Auth ---------------------------
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()

# --------------------------- Socket.IO Events ---------------------------
@socketio.on('connect')
def handle_connect():
    if current_user.is_authenticated:
        current_user.online = True
        db.session.commit()
        emit('user_status', {'user_id': current_user.id, 'online': True}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if current_user.is_authenticated:
        current_user.online = False
        current_user.last_seen = datetime.utcnow()
        db.session.commit()
        emit('user_status', {'user_id': current_user.id, 'online': False}, broadcast=True)

@socketio.on('join_chat')
def handle_join_chat(data):
    room = get_chat_room(current_user.id, data['recipient_id'])
    join_room(room)
    emit('joined_chat', {'room': room})

@socketio.on('send_message')
def handle_send_message(data):
    recipient_id = data.get('recipient_id')
    content = data.get('content')

    if not recipient_id or not content:
        emit('error', {'message': 'Invalid message data'})
        return

    message = Message(sender_id=current_user.id, recipient_id=recipient_id, content=content)
    db.session.add(message)
    db.session.commit()

    message_data = {
        'id': message.id,
        'sender_id': message.sender_id,
        'sender_name': current_user.username,
        'recipient_id': message.recipient_id,
        'content': message.content,
        'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M'),
        'read': message.read
    }

    room = get_chat_room(current_user.id, recipient_id)
    emit('receive_message', message_data, room=room)

def get_chat_room(user1_id, user2_id):
    return f"chat_{min(user1_id, user2_id)}_{max(user1_id, user2_id)}"

# --------------------------- Routes ---------------------------
@app.route('/')
def home():
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if User.query.filter_by(username=username).first():
            flash('Username already exists.', 'danger')
            return redirect(url_for('register'))

        new_user = User(username=username, password=generate_password_hash(password))
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            login_user(user)
            user.online = True
            db.session.commit()
            return redirect(url_for('dashboard'))
        flash('Invalid username or password.', 'danger')

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    current_user.online = False
    current_user.last_seen = datetime.utcnow()
    db.session.commit()
    logout_user()
    return redirect(url_for('login'))

@app.route('/dashboard')
@login_required
def dashboard():
    online_users = User.query.filter(User.id != current_user.id, User.online == True).all()
    return render_template('dashboard.html', online_users=online_users)

@app.route('/chat/<int:recipient_id>')
@login_required
def chat(recipient_id):
    recipient = User.query.get_or_404(recipient_id)

    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == recipient.id)) |
        ((Message.sender_id == recipient.id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()

    # Mark messages as read
    for msg in messages:
        if msg.recipient_id == current_user.id and not msg.read:
            msg.read = True
    db.session.commit()

    return render_template('chat.html', recipient=recipient, messages=messages)

@app.route('/api/online_users')
@login_required
def get_online_users():
    users = User.query.filter(User.id != current_user.id, User.online == True).all()
    return jsonify([{'id': u.id, 'username': u.username} for u in users])

# --------------------------- Optional: Initialize Database ---------------------------
def initialize_database():
    with app.app_context():
        db.create_all()
        if not User.query.filter_by(username='user1').first():
            db.session.add(User(username='user1', password=generate_password_hash('password1')))
        if not User.query.filter_by(username='user2').first():
            db.session.add(User(username='user2', password=generate_password_hash('password2')))
        db.session.commit()

# --------------------------- Run ---------------------------
if __name__ == '__main__':
    debug_mode = os.getenv('DEBUG', 'false').lower() == 'true'
    # initialize_database()  # Run once if needed
    socketio.run(app, host="0.0.0.0", port=5000, debug=debug_mode)
