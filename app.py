from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv
from flask_socketio import SocketIO, emit, join_room, leave_room
from flask_migrate import Migrate

load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY') or 'your-secret-key-here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///messaging.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

db = SQLAlchemy(app)
migrate = Migrate(app, db)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
socketio = SocketIO(app)

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    last_seen = db.Column(db.DateTime, default=datetime.utcnow)
    online = db.Column(db.Boolean, default=False)
    
    def is_online(self):
        return self.online

# Message model
class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    read = db.Column(db.Boolean, default=False)
    
    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.before_request
def before_request():
    if current_user.is_authenticated:
        current_user.last_seen = datetime.utcnow()
        db.session.commit()

# SocketIO Events
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
    if current_user.is_authenticated:
        recipient_id = data['recipient_id']
        room = get_chat_room(current_user.id, recipient_id)
        join_room(room)
        emit('joined_chat', {'room': room})

@socketio.on('send_message')
def handle_send_message(data):
    if current_user.is_authenticated:
        recipient_id = data['recipient_id']
        content = data['content']
        
        # Save message to database
        message = Message(
            sender_id=current_user.id,
            recipient_id=recipient_id,
            content=content
        )
        db.session.add(message)
        db.session.commit()
        
        # Prepare message data for sending
        message_data = {
            'id': message.id,
            'sender_id': message.sender_id,
            'sender_name': current_user.username,
            'recipient_id': message.recipient_id,
            'content': message.content,
            'timestamp': message.timestamp.strftime('%Y-%m-%d %H:%M'),
            'read': message.read
        }
        
        # Send to both users in the chat room
        room = get_chat_room(current_user.id, recipient_id)
        emit('receive_message', message_data, room=room)

def get_chat_room(user1_id, user2_id):
    ids = sorted([user1_id, user2_id])
    return f"chat_{ids[0]}_{ids[1]}"

# Routes
@app.route('/')
def home():
    return redirect(url_for('dashboard'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists. Please choose another.', 'danger')
            return redirect(url_for('register'))
        
        new_user = User(username=username, password=password)
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
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.password == password:
            login_user(user)
            user.online = True
            db.session.commit()
            return redirect(url_for('dashboard'))
        else:
            flash('Login failed. Check your username and password.', 'danger')
    
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
    online_users = User.query.filter_by(online=True).all()
    return render_template('dashboard.html', online_users=online_users)

@app.route('/chat/<int:recipient_id>')
@login_required
def chat(recipient_id):
    recipient = User.query.get_or_404(recipient_id)
    
    # Get messages between current user and recipient
    messages = Message.query.filter(
        ((Message.sender_id == current_user.id) & (Message.recipient_id == recipient.id)) |
        ((Message.sender_id == recipient.id) & (Message.recipient_id == current_user.id))
    ).order_by(Message.timestamp.asc()).all()
    
    # Mark received messages as read
    for message in messages:
        if message.recipient_id == current_user.id and not message.read:
            message.read = True
            db.session.commit()
    
    return render_template('chat.html', recipient=recipient, messages=messages)

@app.route('/api/online_users')
@login_required
def online_users():
    online_users = User.query.filter_by(online=True).all()
    return jsonify([{'id': user.id, 'username': user.username} for user in online_users])

# Initialize database
def initialize_database():
    with app.app_context():
        db.create_all()
        # Create test users if they don't exist
        if not User.query.filter_by(username='user1').first():
            user1 = User(username='user1', password='password1')
            db.session.add(user1)
        if not User.query.filter_by(username='user2').first():
            user2 = User(username='user2', password='password2')
            db.session.add(user2)
        db.session.commit()

if __name__ == '__main__':
    #initialize_database()
    socketio.run(app)
