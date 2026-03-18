from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(UserMixin, db.Model):
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    bio = db.Column(db.Text, nullable=True)
    role = db.Column(db.String(20), default='student')
    profile_pic = db.Column(db.String(200), default='default.jpg')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_active = db.Column(db.Boolean, default=True)
    
    # Relationships
    preference = db.relationship('Preference', backref='user', uselist=False, cascade='all, delete-orphan')
    sent_requests = db.relationship('MatchRequest', foreign_keys='MatchRequest.sender_id', backref='sender', lazy=True)
    received_requests = db.relationship('MatchRequest', foreign_keys='MatchRequest.receiver_id', backref='receiver', lazy=True)
    applications = db.relationship('Application', backref='student', lazy=True)
    agreements = db.relationship('Agreement', backref='student', lazy=True)
    sent_messages = db.relationship('Message', foreign_keys='Message.sender_id', backref='sender', lazy=True)
    received_messages = db.relationship('Message', foreign_keys='Message.receiver_id', backref='receiver', lazy=True)
    checklist_items = db.relationship('ChecklistItem', backref='student', lazy=True)
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    def get_full_name(self):
        return f"{self.first_name} {self.last_name}"
    
    def get_confirmed_matches(self):
        """Get all confirmed matches where user is either sender or receiver"""
        as_sender = MatchRequest.query.filter_by(sender_id=self.id, status='accepted').all()
        as_receiver = MatchRequest.query.filter_by(receiver_id=self.id, status='accepted').all()
        return as_sender + as_receiver

class Preference(db.Model):
    __tablename__ = 'preferences'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False, unique=True)
    
    # Lifestyle preferences
    sleep_schedule = db.Column(db.String(20))  # early, night, flexible
    study_habits = db.Column(db.String(20))    # quiet, moderate, group
    cleanliness = db.Column(db.Integer)         # 1-5 scale
    guests_frequency = db.Column(db.String(20)) # rarely, sometimes, often
    smoking = db.Column(db.Boolean, default=False)
    pets = db.Column(db.Boolean, default=False)
    
    # Budget preferences (in Rands)
    budget_min = db.Column(db.Float)
    budget_max = db.Column(db.Float)
    
    # Location preferences
    preferred_area = db.Column(db.String(100))
    distance_to_campus = db.Column(db.String(20))
    
    # Personal info
    age = db.Column(db.Integer)
    gender = db.Column(db.String(20))
    course = db.Column(db.String(100))
    year_of_study = db.Column(db.Integer)
    
    # Housing preferences (ranked choices)
    housing_choice1 = db.Column(db.Integer, db.ForeignKey('housing.id'), nullable=True)
    housing_choice2 = db.Column(db.Integer, db.ForeignKey('housing.id'), nullable=True)
    housing_choice3 = db.Column(db.Integer, db.ForeignKey('housing.id'), nullable=True)
    
    # Additional
    hobbies = db.Column(db.Text)
    additional_notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships for housing choices
    choice1 = db.relationship('Housing', foreign_keys=[housing_choice1])
    choice2 = db.relationship('Housing', foreign_keys=[housing_choice2])
    choice3 = db.relationship('Housing', foreign_keys=[housing_choice3])

class MatchRequest(db.Model):
    __tablename__ = 'match_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')  # pending, accepted, rejected, finalised
    compatibility_score = db.Column(db.Float)
    message = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    finalised_at = db.Column(db.DateTime, nullable=True)
    
    __table_args__ = (db.UniqueConstraint('sender_id', 'receiver_id', name='unique_match'),)
    
    def finalise(self):
        """Mark match as finalised after agreement"""
        self.status = 'finalised'
        self.finalised_at = datetime.utcnow()

class Message(db.Model):
    __tablename__ = 'messages'
    
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    match_request_id = db.Column(db.Integer, db.ForeignKey('match_requests.id'), nullable=False)
    content = db.Column(db.Text, nullable=False)
    is_read = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    match_request = db.relationship('MatchRequest', backref='messages')

class ChecklistItem(db.Model):
    __tablename__ = 'checklist_items'
    
    id = db.Column(db.Integer, primary_key=True)
    match_request_id = db.Column(db.Integer, db.ForeignKey('match_requests.id'), nullable=False)
    item_name = db.Column(db.String(100), nullable=False)
    status = db.Column(db.String(20), default='needed')  # needed, i_have, you_bring, split_cost
    price = db.Column(db.Float, nullable=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    match_request = db.relationship('MatchRequest', backref='checklist')
    creator = db.relationship('User', foreign_keys=[created_by])

class Housing(db.Model):
    __tablename__ = 'housing'
    
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=False)
    address = db.Column(db.String(200), nullable=False)
    city = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)  # In Rands
    bedrooms = db.Column(db.Integer)
    bathrooms = db.Column(db.Float)
    square_meters = db.Column(db.Integer)
    furnished = db.Column(db.Boolean, default=False)
    utilities_included = db.Column(db.Boolean, default=False)
    parking = db.Column(db.Boolean, default=False)
    pet_friendly = db.Column(db.Boolean, default=False)
    wifi_included = db.Column(db.Boolean, default=False)
    images = db.Column(db.Text)
    available_from = db.Column(db.Date)
    is_available = db.Column(db.Boolean, default=True)
    created_by = db.Column(db.Integer, db.ForeignKey('users.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    applications = db.relationship('Application', backref='housing', lazy=True)
    group_applications = db.relationship('GroupApplication', backref='housing', lazy=True)

class Application(db.Model):
    __tablename__ = 'applications'
    
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    housing_id = db.Column(db.Integer, db.ForeignKey('housing.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    move_in_date = db.Column(db.Date)
    lease_term = db.Column(db.String(20))
    additional_notes = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class GroupApplication(db.Model):
    __tablename__ = 'group_applications'
    
    id = db.Column(db.Integer, primary_key=True)
    match_request_id = db.Column(db.Integer, db.ForeignKey('match_requests.id'), nullable=False)
    housing_id = db.Column(db.Integer, db.ForeignKey('housing.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    match_request = db.relationship('MatchRequest', backref='group_applications')

class Agreement(db.Model):
    __tablename__ = 'agreements'
    
    id = db.Column(db.Integer, primary_key=True)
    student_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    housing_id = db.Column(db.Integer, db.ForeignKey('housing.id'), nullable=False)
    match_request_id = db.Column(db.Integer, db.ForeignKey('match_requests.id'), nullable=True)
    agreement_text = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='pending')
    signed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    housing = db.relationship('Housing')
    match_request = db.relationship('MatchRequest')

class Notification(db.Model):
    __tablename__ = 'notifications'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    type = db.Column(db.String(50))
    title = db.Column(db.String(200))
    message = db.Column(db.Text)
    is_read = db.Column(db.Boolean, default=False)
    link = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationship
    user = db.relationship('User', backref='notifications')
    