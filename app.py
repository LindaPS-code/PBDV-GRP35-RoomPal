import os
import math
from datetime import datetime, date
from functools import wraps
from werkzeug.utils import secure_filename
from flask import Flask, render_template, redirect, url_for, flash, request, session, jsonify, send_from_directory
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from models import db, User, Preference, MatchRequest, Message, ChecklistItem, Housing, Application, GroupApplication, Agreement, Notification

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-change-this-in-production'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///roommate_app.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db.init_app(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated or current_user.role != 'admin':
            flash('You need admin privileges to access this page.', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

def calculate_compatibility(user1_id, user2_id):
    pref1 = Preference.query.filter_by(user_id=user1_id).first()
    pref2 = Preference.query.filter_by(user_id=user2_id).first()
    
    if not pref1 or not pref2:
        return 0
    
    score = 0
    max_score = 0
    
    # Sleep schedule compatibility (10 points)
    max_score += 10
    if pref1.sleep_schedule == pref2.sleep_schedule:
        score += 10
    elif pref1.sleep_schedule != pref2.sleep_schedule:
        compatible_pairs = {
            ('early', 'flexible'): 7,
            ('night', 'flexible'): 7,
            ('early', 'night'): 3
        }
        key = (pref1.sleep_schedule, pref2.sleep_schedule)
        if key in compatible_pairs:
            score += compatible_pairs[key]
    
    # Study habits compatibility (10 points)
    max_score += 10
    if pref1.study_habits == pref2.study_habits:
        score += 10
    elif pref1.study_habits != pref2.study_habits:
        compatible_pairs = {
            ('quiet', 'moderate'): 8,
            ('moderate', 'group'): 8,
            ('quiet', 'group'): 4
        }
        key = (pref1.study_habits, pref2.study_habits)
        if key in compatible_pairs:
            score += compatible_pairs[key]
    
    # Cleanliness compatibility (15 points)
    max_score += 15
    cleanliness_diff = abs(pref1.cleanliness - pref2.cleanliness)
    score += max(0, 15 - (cleanliness_diff * 3))
    
    # Guest frequency compatibility (10 points)
    max_score += 10
    guest_values = {'rarely': 1, 'sometimes': 2, 'often': 3}
    if pref1.guests_frequency and pref2.guests_frequency:
        guest_diff = abs(guest_values.get(pref1.guests_frequency, 2) - guest_values.get(pref2.guests_frequency, 2))
        score += max(0, 10 - (guest_diff * 3))
    
    # Smoking compatibility (10 points)
    max_score += 10
    if pref1.smoking == pref2.smoking:
        score += 10
    
    # Pets compatibility (10 points)
    max_score += 10
    if pref1.pets == pref2.pets:
        score += 10
    
    # Budget compatibility (15 points) in Rands
    max_score += 15
    budget_overlap = min(pref1.budget_max, pref2.budget_max) - max(pref1.budget_min, pref2.budget_min)
    if budget_overlap > 0:
        overlap_ratio = budget_overlap / ((pref1.budget_max - pref1.budget_min + pref2.budget_max - pref2.budget_min) / 2)
        score += min(15, overlap_ratio * 15)
    
    # Age compatibility (5 points)
    max_score += 5
    if pref1.age and pref2.age:
        age_diff = abs(pref1.age - pref2.age)
        if age_diff <= 2:
            score += 5
        elif age_diff <= 4:
            score += 3
    
    # Course compatibility (5 points)
    max_score += 5
    if pref1.course and pref2.course:
        if pref1.course == pref2.course:
            score += 5
        elif pref1.course.split()[0] == pref2.course.split()[0]:
            score += 3
    
    # Hobbies compatibility (10 points)
    max_score += 10
    if pref1.hobbies and pref2.hobbies:
        hobbies1 = set(pref1.hobbies.lower().split(','))
        hobbies2 = set(pref2.hobbies.lower().split(','))
        common_hobbies = len(hobbies1.intersection(hobbies2))
        score += min(10, common_hobbies * 2)
    
    return (score / max_score) * 100 if max_score > 0 else 0

def get_compatibility_insight(user1_id, user2_id):
    """Generate smart insights about compatibility"""
    user1 = User.query.get(user1_id)
    user2 = User.query.get(user2_id)
    pref1 = Preference.query.filter_by(user_id=user1_id).first()
    pref2 = Preference.query.filter_by(user_id=user2_id).first()
    
    insights = []
    
    if pref1 and pref2:
        if pref1.sleep_schedule == pref2.sleep_schedule:
            insights.append(f"Both {'early birds' if pref1.sleep_schedule == 'early' else 'night owls'} - perfect for quiet nights!")
        else:
            insights.append("Different sleep schedules - communication is key!")
        
        cleanliness_diff = abs(pref1.cleanliness - pref2.cleanliness)
        if cleanliness_diff <= 1:
            insights.append("Similar cleanliness standards - your space will stay tidy!")
        elif cleanliness_diff >= 3:
            insights.append("Different cleanliness standards - maybe discuss a cleaning schedule.")
    
    if user1.bio and user2.bio:
        keywords = {'study': 'study buddies', 'music': 'music lovers', 'cooking': 'foodies', 
                   'gaming': 'gamers', 'fitness': 'fitness enthusiasts'}
        for keyword, label in keywords.items():
            if keyword in user1.bio.lower() and keyword in user2.bio.lower():
                insights.append(f"You're both {label} - great for bonding!")
                break
    
    return insights if insights else ["You seem compatible! Get to know each other better."]

# Context processors for template functions
@app.context_processor
def utility_processor():
    from datetime import datetime
    
    def calculate_compatibility(user1_id, user2_id):
        """Calculate compatibility score between two users"""
        pref1 = Preference.query.filter_by(user_id=user1_id).first()
        pref2 = Preference.query.filter_by(user_id=user2_id).first()
        
        if not pref1 or not pref2:
            return 0
        
        score = 0
        max_score = 0
        
        # Sleep schedule compatibility
        max_score += 10
        if pref1.sleep_schedule == pref2.sleep_schedule:
            score += 10
        elif pref1.sleep_schedule != pref2.sleep_schedule:
            compatible_pairs = {
                ('early', 'flexible'): 7,
                ('night', 'flexible'): 7,
                ('early', 'night'): 3
            }
            key = (pref1.sleep_schedule, pref2.sleep_schedule)
            if key in compatible_pairs:
                score += compatible_pairs[key]
        
        # Study habits compatibility
        max_score += 10
        if pref1.study_habits == pref2.study_habits:
            score += 10
        elif pref1.study_habits != pref2.study_habits:
            compatible_pairs = {
                ('quiet', 'moderate'): 8,
                ('moderate', 'group'): 8,
                ('quiet', 'group'): 4
            }
            key = (pref1.study_habits, pref2.study_habits)
            if key in compatible_pairs:
                score += compatible_pairs[key]
        
        # Cleanliness compatibility
        max_score += 15
        cleanliness_diff = abs(pref1.cleanliness - pref2.cleanliness)
        score += max(0, 15 - (cleanliness_diff * 3))
        
        # Guest frequency compatibility
        max_score += 10
        guest_values = {'rarely': 1, 'sometimes': 2, 'often': 3}
        if pref1.guests_frequency and pref2.guests_frequency:
            guest_diff = abs(guest_values.get(pref1.guests_frequency, 2) - guest_values.get(pref2.guests_frequency, 2))
            score += max(0, 10 - (guest_diff * 3))
        
        # Smoking compatibility
        max_score += 10
        if pref1.smoking == pref2.smoking:
            score += 10
        
        # Pets compatibility
        max_score += 10
        if pref1.pets == pref2.pets:
            score += 10
        
        # Budget compatibility (in Rands)
        max_score += 15
        budget_overlap = min(pref1.budget_max, pref2.budget_max) - max(pref1.budget_min, pref2.budget_min)
        if budget_overlap > 0:
            overlap_ratio = budget_overlap / ((pref1.budget_max - pref1.budget_min + pref2.budget_max - pref2.budget_min) / 2)
            score += min(15, overlap_ratio * 15)
        
        # Age compatibility
        max_score += 5
        if pref1.age and pref2.age:
            age_diff = abs(pref1.age - pref2.age)
            if age_diff <= 2:
                score += 5
            elif age_diff <= 4:
                score += 3
        
        # Course compatibility
        max_score += 5
        if pref1.course and pref2.course:
            if pref1.course == pref2.course:
                score += 5
            elif pref1.course.split()[0] == pref2.course.split()[0]:
                score += 3
        
        # Hobbies compatibility
        max_score += 10
        if pref1.hobbies and pref2.hobbies:
            hobbies1 = set(pref1.hobbies.lower().split(','))
            hobbies2 = set(pref2.hobbies.lower().split(','))
            common_hobbies = len(hobbies1.intersection(hobbies2))
            score += min(10, common_hobbies * 2)
        
        # Bio keyword matching (smart insights)
        max_score += 10
        user1 = User.query.get(user1_id)
        user2 = User.query.get(user2_id)
        if user1.bio and user2.bio:
            keywords = ['study', 'music', 'sport', 'cooking', 'gaming', 'reading', 'travel', 'fitness']
            bio1_lower = user1.bio.lower()
            bio2_lower = user2.bio.lower()
            for keyword in keywords:
                if keyword in bio1_lower and keyword in bio2_lower:
                    score += 2
        
        return (score / max_score) * 100 if max_score > 0 else 0
    
    def get_compatibility_insight(user1_id, user2_id):
        """Generate smart insights about compatibility"""
        user1 = User.query.get(user1_id)
        user2 = User.query.get(user2_id)
        pref1 = Preference.query.filter_by(user_id=user1_id).first()
        pref2 = Preference.query.filter_by(user_id=user2_id).first()
        
        insights = []
        
        if pref1 and pref2:
            if pref1.sleep_schedule == pref2.sleep_schedule:
                insights.append(f"Both {'early birds' if pref1.sleep_schedule == 'early' else 'night owls'} - perfect for quiet nights!")
            else:
                insights.append("Different sleep schedules - communication is key!")
            
            cleanliness_diff = abs(pref1.cleanliness - pref2.cleanliness)
            if cleanliness_diff <= 1:
                insights.append("Similar cleanliness standards - your space will stay tidy!")
            elif cleanliness_diff >= 3:
                insights.append("Different cleanliness standards - maybe discuss a cleaning schedule.")
        
        if user1.bio and user2.bio:
            keywords = {'study': 'study buddies', 'music': 'music lovers', 'cooking': 'foodies', 
                       'gaming': 'gamers', 'fitness': 'fitness enthusiasts'}
            for keyword, label in keywords.items():
                if keyword in user1.bio.lower() and keyword in user2.bio.lower():
                    insights.append(f"You're both {label} - great for bonding!")
                    break
        
        return insights if insights else ["You seem compatible! Get to know each other better."]
    
    return dict(
        calculate_compatibility=calculate_compatibility,
        get_compatibility_insight=get_compatibility_insight,
        now=datetime.now
    )

# ==================== MAIN ROUTES ====================

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        first_name = request.form.get('first_name')
        last_name = request.form.get('last_name')
        bio = request.form.get('bio', '')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists', 'danger')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            email=email,
            first_name=first_name,
            last_name=last_name,
            bio=bio,
            role='student'
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        user = User.query.filter_by(username=username).first()
        
        if user and user.check_password(password):
            login_user(user)
            
            notification = Notification(
                user_id=user.id,
                type='login',
                title='Welcome back!',
                message=f'Welcome to Roommate Finder, {user.first_name}!',
                link='#'
            )
            db.session.add(notification)
            db.session.commit()
            
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('student_dashboard'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

# ==================== STUDENT DASHBOARD ====================

@app.route('/student/dashboard')
@login_required
def student_dashboard():
    if current_user.role != 'student':
        return redirect(url_for('admin_dashboard'))
    
    notifications = Notification.query.filter_by(user_id=current_user.id, is_read=False).order_by(Notification.created_at.desc()).limit(5).all()
    pending_requests = MatchRequest.query.filter_by(receiver_id=current_user.id, status='pending').count()
    
    recent_matches = MatchRequest.query.filter(
        ((MatchRequest.sender_id == current_user.id) | (MatchRequest.receiver_id == current_user.id)) &
        (MatchRequest.status == 'accepted')
    ).order_by(MatchRequest.updated_at.desc()).limit(5).all()
    
    # Get finalised matches
    finalised_matches = MatchRequest.query.filter(
        ((MatchRequest.sender_id == current_user.id) | (MatchRequest.receiver_id == current_user.id)) &
        (MatchRequest.status == 'finalised')
    ).count()
    
    return render_template('student_dashboard.html', 
                         notifications=notifications,
                         pending_requests=pending_requests,
                         recent_matches=recent_matches,
                         finalised_matches=finalised_matches)

# ==================== PROFILE ROUTES ====================

@app.route('/profile')
@login_required
def profile():
    return render_template('profile.html')

@app.route('/profile/edit', methods=['GET', 'POST'])
@login_required
def edit_profile():
    if request.method == 'POST':
        current_user.first_name = request.form.get('first_name')
        current_user.last_name = request.form.get('last_name')
        current_user.email = request.form.get('email')
        current_user.bio = request.form.get('bio')
        
        if 'profile_pic' in request.files:
            file = request.files['profile_pic']
            if file and allowed_file(file.filename):
                filename = secure_filename(f"user_{current_user.id}_{file.filename}")
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                current_user.profile_pic = filename
        
        db.session.commit()
        flash('Profile updated successfully!', 'success')
        return redirect(url_for('profile'))
    
    return render_template('edit_profile.html')

# ==================== PREFERENCE FORM ====================

@app.route('/preference/form', methods=['GET', 'POST'])
@login_required
def preference_form():
    preference = Preference.query.filter_by(user_id=current_user.id).first()
    housing_list = Housing.query.filter_by(is_available=True).all()
    
    if request.method == 'POST':
        if not preference:
            preference = Preference(user_id=current_user.id)
        
        preference.sleep_schedule = request.form.get('sleep_schedule')
        preference.study_habits = request.form.get('study_habits')
        
        cleanliness_val = request.form.get('cleanliness')
        preference.cleanliness = int(cleanliness_val) if cleanliness_val else 3
        
        preference.guests_frequency = request.form.get('guests_frequency')
        preference.smoking = 'smoking' in request.form
        preference.pets = 'pets' in request.form
        
        budget_min_val = request.form.get('budget_min')
        budget_max_val = request.form.get('budget_max')
        preference.budget_min = float(budget_min_val) if budget_min_val else 0
        preference.budget_max = float(budget_max_val) if budget_max_val else 0
        
        preference.preferred_area = request.form.get('preferred_area')
        preference.distance_to_campus = request.form.get('distance_to_campus')
        
        age_val = request.form.get('age')
        preference.age = int(age_val) if age_val and age_val.strip() else None
        
        preference.gender = request.form.get('gender')
        preference.course = request.form.get('course')
        
        year_val = request.form.get('year_of_study')
        preference.year_of_study = int(year_val) if year_val else 1
        
        # Housing preferences (ranked choices)
        choice1 = request.form.get('housing_choice1')
        choice2 = request.form.get('housing_choice2')
        choice3 = request.form.get('housing_choice3')
        
        preference.housing_choice1 = int(choice1) if choice1 and choice1 != '' else None
        preference.housing_choice2 = int(choice2) if choice2 and choice2 != '' else None
        preference.housing_choice3 = int(choice3) if choice3 and choice3 != '' else None
        
        preference.hobbies = request.form.get('hobbies')
        preference.additional_notes = request.form.get('additional_notes')
        
        if not preference.id:
            db.session.add(preference)
        db.session.commit()
        
        flash('Preferences saved successfully!', 'success')
        return redirect(url_for('matches'))
    
    return render_template('preference_form.html', preference=preference, housing_list=housing_list)

# ==================== MATCHES ====================

@app.route('/matches')
@login_required
def matches():
    if current_user.role != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    user_pref = Preference.query.filter_by(user_id=current_user.id).first()
    
    if not user_pref:
        flash('Please complete your preference form first', 'warning')
        return redirect(url_for('preference_form'))
    
    # Get all students except current user and those already matched/finalised
    other_students = User.query.filter(
        User.id != current_user.id,
        User.role == 'student',
        User.preference != None
    ).all()
    
    # Get all matches involving current user
    user_matches = MatchRequest.query.filter(
        (MatchRequest.sender_id == current_user.id) | (MatchRequest.receiver_id == current_user.id)
    ).all()
    
    # Create set of user IDs that are already matched or finalised
    excluded_user_ids = set()
    for match in user_matches:
        if match.status in ['accepted', 'finalised']:
            other_id = match.sender_id if match.receiver_id == current_user.id else match.receiver_id
            excluded_user_ids.add(other_id)
    
    matches_data = []
    pending_requests = []
    
    for student in other_students:
        if student.id in excluded_user_ids:
            continue
            
        score = calculate_compatibility(current_user.id, student.id)
        
        existing_request = MatchRequest.query.filter(
            ((MatchRequest.sender_id == current_user.id) & (MatchRequest.receiver_id == student.id)) |
            ((MatchRequest.sender_id == student.id) & (MatchRequest.receiver_id == current_user.id))
        ).first()
        
        status = None
        request_id = None
        is_receiver = False
        
        if existing_request:
            status = existing_request.status
            request_id = existing_request.id
            if existing_request.receiver_id == current_user.id and existing_request.status == 'pending':
                is_receiver = True
                pending_requests.append({
                    'user': student,
                    'score': round(score, 1),
                    'request_id': request_id,
                    'message': existing_request.message,
                    'insights': get_compatibility_insight(current_user.id, student.id)
                })
        
        if score >= 50:  # Only show matches with 50%+ compatibility
            matches_data.append({
                'user': student,
                'score': round(score, 1),
                'status': status,
                'request_id': request_id,
                'is_receiver': is_receiver,
                'insights': get_compatibility_insight(current_user.id, student.id) if not existing_request else []
            })
    
    matches_data.sort(key=lambda x: x['score'], reverse=True)
    
    return render_template('matches.html', 
                         matches=matches_data, 
                         pending_requests=pending_requests)

@app.route('/send_match_request/<int:receiver_id>', methods=['POST'])
@login_required
def send_match_request(receiver_id):
    if current_user.id == receiver_id:
        return jsonify({'error': 'Cannot send request to yourself'}), 400
    
    # Check if already matched
    existing = MatchRequest.query.filter(
        ((MatchRequest.sender_id == current_user.id) & (MatchRequest.receiver_id == receiver_id)) |
        ((MatchRequest.sender_id == receiver_id) & (MatchRequest.receiver_id == current_user.id))
    ).first()
    
    if existing:
        return jsonify({'error': 'Match request already exists'}), 400
    
    score = calculate_compatibility(current_user.id, receiver_id)
    
    match_request = MatchRequest(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        compatibility_score=score,
        message=request.json.get('message', '')
    )
    
    db.session.add(match_request)
    
    notification = Notification(
        user_id=receiver_id,
        type='match_request',
        title='New Match Request',
        message=f'{current_user.get_full_name()} wants to be your roommate!',
        link='/matches'
    )
    db.session.add(notification)
    
    db.session.commit()
    
    return jsonify({'success': True, 'score': score})

@app.route('/respond_match_request/<int:request_id>/<string:action>', methods=['POST'])
@login_required
def respond_match_request(request_id, action):
    match_request = MatchRequest.query.get_or_404(request_id)
    
    if match_request.receiver_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if action == 'accept':
        match_request.status = 'accepted'
        
        notification = Notification(
            user_id=match_request.sender_id,
            type='match_accepted',
            title='Match Request Accepted',
            message=f'{current_user.get_full_name()} accepted your roommate request!',
            link='/matches'
        )
        db.session.add(notification)
        
    elif action == 'reject':
        match_request.status = 'rejected'
    
    match_request.updated_at = datetime.utcnow()
    db.session.commit()
    
    return jsonify({'success': True})

# ==================== CHAT SYSTEM ====================

@app.route('/chat/<int:match_id>')
@login_required
def chat(match_id):
    match_request = MatchRequest.query.get_or_404(match_id)
    
    # Verify user is part of this match
    if match_request.sender_id != current_user.id and match_request.receiver_id != current_user.id:
        flash('Unauthorized', 'danger')
        return redirect(url_for('matches'))
    
    # Only allow chat if match is accepted or finalised
    if match_request.status not in ['accepted', 'finalised']:
        flash('Chat is only available for confirmed matches', 'warning')
        return redirect(url_for('matches'))
    
    # Get the other user
    other_user_id = match_request.sender_id if match_request.receiver_id == current_user.id else match_request.receiver_id
    other_user = User.query.get(other_user_id)
    
    # Get messages
    messages = Message.query.filter_by(match_request_id=match_id).order_by(Message.created_at).all()
    
    # Mark messages as read
    for msg in messages:
        if msg.receiver_id == current_user.id and not msg.is_read:
            msg.is_read = True
    db.session.commit()
    
    return render_template('chat.html', 
                         match=match_request, 
                         other_user=other_user, 
                         messages=messages)

@app.route('/send_message/<int:match_id>', methods=['POST'])
@login_required
def send_message(match_id):
    match_request = MatchRequest.query.get_or_404(match_id)
    
    if match_request.sender_id != current_user.id and match_request.receiver_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    content = request.json.get('content')
    if not content:
        return jsonify({'error': 'Message cannot be empty'}), 400
    
    receiver_id = match_request.sender_id if match_request.receiver_id == current_user.id else match_request.receiver_id
    
    message = Message(
        sender_id=current_user.id,
        receiver_id=receiver_id,
        match_request_id=match_id,
        content=content
    )
    
    db.session.add(message)
    
    # Create notification
    notification = Notification(
        user_id=receiver_id,
        type='new_message',
        title='New Message',
        message=f'{current_user.get_full_name()} sent you a message',
        link=f'/chat/{match_id}'
    )
    db.session.add(notification)
    
    db.session.commit()
    
    return jsonify({
        'success': True,
        'message': {
            'id': message.id,
            'content': message.content,
            'created_at': message.created_at.strftime('%H:%M'),
            'sender_id': message.sender_id
        }
    })

# ==================== CHECKLIST SYSTEM ====================

@app.route('/checklist/<int:match_id>')
@login_required
def checklist(match_id):
    match_request = MatchRequest.query.get_or_404(match_id)
    
    if match_request.sender_id != current_user.id and match_request.receiver_id != current_user.id:
        flash('Unauthorized', 'danger')
        return redirect(url_for('matches'))
    
    if match_request.status not in ['accepted', 'finalised']:
        flash('Checklist is only available for confirmed matches', 'warning')
        return redirect(url_for('matches'))
    
    checklist_items = ChecklistItem.query.filter_by(match_request_id=match_id).order_by(ChecklistItem.created_at).all()
    
    # Calculate split costs
    total_cost = 0
    split_items = [item for item in checklist_items if item.status == 'split_cost' and item.price]
    if split_items:
        total_cost = sum(item.price for item in split_items)
    cost_per_person = total_cost / 2 if total_cost > 0 else 0
    
    other_user_id = match_request.sender_id if match_request.receiver_id == current_user.id else match_request.receiver_id
    other_user = User.query.get(other_user_id)
    
    return render_template('checklist.html',
                         match=match_request,
                         other_user=other_user,
                         items=checklist_items,
                         total_cost=total_cost,
                         cost_per_person=cost_per_person)

@app.route('/checklist/add_item/<int:match_id>', methods=['POST'])
@login_required
def add_checklist_item(match_id):
    match_request = MatchRequest.query.get_or_404(match_id)
    
    if match_request.sender_id != current_user.id and match_request.receiver_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    item_name = request.json.get('item_name')
    if not item_name:
        return jsonify({'error': 'Item name required'}), 400
    
    item = ChecklistItem(
        match_request_id=match_id,
        item_name=item_name,
        status='needed',
        created_by=current_user.id
    )
    
    db.session.add(item)
    db.session.commit()
    
    return jsonify({
        'success': True,
        'item': {
            'id': item.id,
            'name': item.item_name,
            'status': item.status,
            'price': item.price
        }
    })

@app.route('/checklist/update_item/<int:item_id>', methods=['POST'])
@login_required
def update_checklist_item(item_id):
    item = ChecklistItem.query.get_or_404(item_id)
    match_request = item.match_request
    
    if match_request.sender_id != current_user.id and match_request.receiver_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    status = request.json.get('status')
    price = request.json.get('price')
    
    if status:
        item.status = status
    
    if price is not None:
        item.price = float(price) if price else None
    
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/checklist/delete_item/<int:item_id>', methods=['POST'])
@login_required
def delete_checklist_item(item_id):
    item = ChecklistItem.query.get_or_404(item_id)
    match_request = item.match_request
    
    if match_request.sender_id != current_user.id and match_request.receiver_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    db.session.delete(item)
    db.session.commit()
    
    return jsonify({'success': True})

# ==================== HOUSING ====================

@app.route('/housing')
@login_required
def housing_listings():
    min_price = request.args.get('min_price', type=float)
    max_price = request.args.get('max_price', type=float)
    bedrooms = request.args.get('bedrooms', type=int)
    furnished = request.args.get('furnished') == 'on'
    pet_friendly = request.args.get('pet_friendly') == 'on'
    city = request.args.get('city')
    
    query = Housing.query.filter_by(is_available=True)
    
    if min_price:
        query = query.filter(Housing.price >= min_price)
    if max_price:
        query = query.filter(Housing.price <= max_price)
    if bedrooms:
        query = query.filter(Housing.bedrooms >= bedrooms)
    if furnished:
        query = query.filter_by(furnished=True)
    if pet_friendly:
        query = query.filter_by(pet_friendly=True)
    if city:
        query = query.filter(Housing.city.ilike(f'%{city}%'))
    
    listings = query.order_by(Housing.created_at.desc()).all()
    
    # Get unique cities for filter dropdown
    cities = db.session.query(Housing.city).distinct().all()
    cities = [city[0] for city in cities]
    
    match_id = request.args.get('match_id')
    
    return render_template('housing_listings.html', 
                         listings=listings, 
                         cities=cities,
                         match_id=match_id)

@app.route('/housing/<int:housing_id>')
@login_required
def housing_detail(housing_id):
    housing = Housing.query.get_or_404(housing_id)
    
    existing_application = Application.query.filter_by(
        student_id=current_user.id,
        housing_id=housing_id
    ).first() if current_user.role == 'student' else None
    
    match_id = request.args.get('match_id')
    
    return render_template('housing_detail.html', 
                         housing=housing, 
                         application=existing_application,
                         match_id=match_id)

@app.route('/apply_housing/<int:housing_id>', methods=['POST'])
@login_required
def apply_housing(housing_id):
    if current_user.role != 'student':
        return jsonify({'error': 'Only students can apply'}), 403
    
    housing = Housing.query.get_or_404(housing_id)
    
    if not housing.is_available:
        return jsonify({'error': 'This housing is no longer available'}), 400
    
    existing = Application.query.filter_by(
        student_id=current_user.id,
        housing_id=housing_id
    ).first()
    
    if existing:
        return jsonify({'error': 'You have already applied for this housing'}), 400
    
    application = Application(
        student_id=current_user.id,
        housing_id=housing_id,
        move_in_date=datetime.strptime(request.json.get('move_in_date'), '%Y-%m-%d') if request.json.get('move_in_date') else None,
        lease_term=request.json.get('lease_term'),
        additional_notes=request.json.get('additional_notes', '')
    )
    
    db.session.add(application)
    
    admin = User.query.filter_by(role='admin').first()
    if admin:
        notification = Notification(
            user_id=admin.id,
            type='new_application',
            title='New Housing Application',
            message=f'{current_user.get_full_name()} applied for {housing.title}',
            link='/admin/applications'
        )
        db.session.add(notification)
    
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/housing/<int:housing_id>/apply_with_match/<int:match_id>')
@login_required
def apply_with_match(housing_id, match_id):
    if current_user.role != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    housing = Housing.query.get_or_404(housing_id)
    match_request = MatchRequest.query.get_or_404(match_id)
    
    if match_request.sender_id != current_user.id and match_request.receiver_id != current_user.id:
        flash('Unauthorized', 'danger')
        return redirect(url_for('housing_detail', housing_id=housing_id))
    
    if match_request.status != 'accepted':
        flash('You can only apply together with confirmed matches', 'warning')
        return redirect(url_for('housing_detail', housing_id=housing_id))
    
    roommate_id = match_request.sender_id if match_request.receiver_id == current_user.id else match_request.receiver_id
    roommate = User.query.get(roommate_id)
    
    return render_template('housing_group_apply.html', 
                         housing=housing, 
                         match_id=match_id,
                         roommate=roommate)

@app.route('/group_apply/<int:match_id>/<int:housing_id>', methods=['POST'])
@login_required
def group_apply(match_id, housing_id):
    if current_user.role != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    match_request = MatchRequest.query.get_or_404(match_id)
    housing = Housing.query.get_or_404(housing_id)
    
    if match_request.sender_id != current_user.id and match_request.receiver_id != current_user.id:
        flash('Unauthorized', 'danger')
        return redirect(url_for('housing_detail', housing_id=housing_id))
    
    existing = GroupApplication.query.filter_by(
        match_request_id=match_id,
        housing_id=housing_id
    ).first()
    
    if existing:
        flash('You have already applied for this housing as a group', 'warning')
        return redirect(url_for('my_applications'))
    
    group_application = GroupApplication(
        match_request_id=match_id,
        housing_id=housing_id,
        status='pending'
    )
    
    db.session.add(group_application)
    
    admin = User.query.filter_by(role='admin').first()
    if admin:
        notification = Notification(
            user_id=admin.id,
            type='group_application',
            title='New Group Application',
            message=f'Roommate group applied for {housing.title}',
            link='/admin/applications'
        )
        db.session.add(notification)
    
    db.session.commit()
    
    flash('Group application submitted successfully!', 'success')
    return redirect(url_for('my_applications'))

# ==================== APPLICATIONS ====================

@app.route('/applications')
@login_required
def my_applications():
    if current_user.role != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    individual_apps = Application.query.filter_by(student_id=current_user.id).order_by(Application.created_at.desc()).all()
    
    # Get group applications where user is part of the match
    user_matches = MatchRequest.query.filter(
        (MatchRequest.sender_id == current_user.id) | (MatchRequest.receiver_id == current_user.id)
    ).all()
    match_ids = [m.id for m in user_matches]
    group_apps = GroupApplication.query.filter(GroupApplication.match_request_id.in_(match_ids)).order_by(GroupApplication.created_at.desc()).all()
    
    return render_template('applications.html', 
                         individual_apps=individual_apps,
                         group_apps=group_apps)

# ==================== AGREEMENTS ====================

@app.route('/agreements')
@login_required
def my_agreements():
    if current_user.role != 'student':
        flash('Access denied', 'danger')
        return redirect(url_for('index'))
    
    agreements = Agreement.query.filter_by(student_id=current_user.id).order_by(Agreement.created_at.desc()).all()
    return render_template('agreements.html', agreements=agreements)

@app.route('/agreement/<int:agreement_id>/respond/<string:action>', methods=['POST'])
@login_required
def respond_agreement(agreement_id, action):
    agreement = Agreement.query.get_or_404(agreement_id)
    
    if agreement.student_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    if action == 'confirm':
        agreement.status = 'confirmed'
        agreement.signed_at = datetime.utcnow()
        
        # If this is a group agreement, finalise the match
        if agreement.match_request_id:
            match = MatchRequest.query.get(agreement.match_request_id)
            if match:
                match.finalise()
                
    elif action == 'reject':
        agreement.status = 'rejected'
    
    db.session.commit()
    
    return jsonify({'success': True})

# ==================== NOTIFICATIONS ====================

@app.route('/notifications')
@login_required
def get_notifications():
    notifications = Notification.query.filter_by(
        user_id=current_user.id,
        is_read=False
    ).order_by(Notification.created_at.desc()).all()
    
    return jsonify([{
        'id': n.id,
        'title': n.title,
        'message': n.message,
        'type': n.type,
        'link': n.link,
        'created_at': n.created_at.strftime('%Y-%m-%d %H:%M')
    } for n in notifications])

@app.route('/notifications/mark_read/<int:notification_id>', methods=['POST'])
@login_required
def mark_notification_read(notification_id):
    notification = Notification.query.get_or_404(notification_id)
    
    if notification.user_id != current_user.id:
        return jsonify({'error': 'Unauthorized'}), 403
    
    notification.is_read = True
    db.session.commit()
    
    return jsonify({'success': True})

# ==================== ADMIN ROUTES ====================

@app.route('/admin/dashboard')
@login_required
@admin_required
def admin_dashboard():
    total_users = User.query.filter_by(role='student').count()
    total_housing = Housing.query.count()
    pending_applications = Application.query.filter_by(status='pending').count()
    pending_group_apps = GroupApplication.query.filter_by(status='pending').count()
    active_matches = MatchRequest.query.filter_by(status='accepted').count()
    finalised_matches = MatchRequest.query.filter_by(status='finalised').count()
    
    recent_users = User.query.filter_by(role='student').order_by(User.created_at.desc()).limit(5).all()
    
    return render_template('admin_dashboard.html',
                         total_users=total_users,
                         total_housing=total_housing,
                         pending_applications=pending_applications + pending_group_apps,
                         active_matches=active_matches,
                         finalised_matches=finalised_matches,
                         recent_users=recent_users)

@app.route('/admin/users')
@login_required
@admin_required
def admin_users():
    users = User.query.filter_by(role='student').order_by(User.created_at.desc()).all()
    return render_template('admin_users.html', users=users)

@app.route('/admin/users/reset_password/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_reset_password(user_id):
    user = User.query.get_or_404(user_id)
    temp_password = 'Temp@123'
    user.set_password(temp_password)
    db.session.commit()
    return jsonify({'success': True, 'temp_password': temp_password})

@app.route('/admin/users/toggle_active/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def admin_toggle_active(user_id):
    user = User.query.get_or_404(user_id)
    user.is_active = not user.is_active
    db.session.commit()
    return jsonify({'success': True, 'is_active': user.is_active})

@app.route('/admin/housing')
@login_required
@admin_required
def admin_housing():
    listings = Housing.query.order_by(Housing.created_at.desc()).all()
    return render_template('admin_housing.html', listings=listings)

@app.route('/admin/housing/add', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_add_housing():
    if request.method == 'POST':
        housing = Housing(
            title=request.form.get('title'),
            description=request.form.get('description'),
            address=request.form.get('address'),
            city=request.form.get('city'),
            price=float(request.form.get('price')),
            bedrooms=int(request.form.get('bedrooms', 1)),
            bathrooms=float(request.form.get('bathrooms', 1)),
            square_meters=int(request.form.get('square_meters', 0)),
            furnished='furnished' in request.form,
            utilities_included='utilities_included' in request.form,
            parking='parking' in request.form,
            pet_friendly='pet_friendly' in request.form,
            wifi_included='wifi_included' in request.form,
            available_from=datetime.strptime(request.form.get('available_from'), '%Y-%m-%d') if request.form.get('available_from') else None,
            created_by=current_user.id
        )
        
        images = []
        if 'images' in request.files:
            files = request.files.getlist('images')
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"housing_{datetime.utcnow().timestamp()}_{file.filename}")
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    images.append(filename)
        
        housing.images = ','.join(images) if images else ''
        
        db.session.add(housing)
        db.session.commit()
        
        flash('Housing listing added successfully!', 'success')
        return redirect(url_for('admin_housing'))
    
    return render_template('admin_add_housing.html')

@app.route('/admin/housing/edit/<int:housing_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_edit_housing(housing_id):
    housing = Housing.query.get_or_404(housing_id)
    
    if request.method == 'POST':
        housing.title = request.form.get('title')
        housing.description = request.form.get('description')
        housing.address = request.form.get('address')
        housing.city = request.form.get('city')
        housing.price = float(request.form.get('price'))
        housing.bedrooms = int(request.form.get('bedrooms', 1))
        housing.bathrooms = float(request.form.get('bathrooms', 1))
        housing.square_meters = int(request.form.get('square_meters', 0))
        housing.furnished = 'furnished' in request.form
        housing.utilities_included = 'utilities_included' in request.form
        housing.parking = 'parking' in request.form
        housing.pet_friendly = 'pet_friendly' in request.form
        housing.wifi_included = 'wifi_included' in request.form
        housing.is_available = 'is_available' in request.form
        housing.available_from = datetime.strptime(request.form.get('available_from'), '%Y-%m-%d') if request.form.get('available_from') else None
        
        if 'images' in request.files:
            files = request.files.getlist('images')
            new_images = []
            for file in files:
                if file and allowed_file(file.filename):
                    filename = secure_filename(f"housing_{datetime.utcnow().timestamp()}_{file.filename}")
                    file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                    new_images.append(filename)
            
            if new_images:
                existing_images = housing.images.split(',') if housing.images else []
                housing.images = ','.join(existing_images + new_images)
        
        db.session.commit()
        flash('Housing listing updated successfully!', 'success')
        return redirect(url_for('admin_housing'))
    
    return render_template('admin_edit_housing.html', housing=housing)

@app.route('/admin/housing/delete/<int:housing_id>', methods=['POST'])
@login_required
@admin_required
def admin_delete_housing(housing_id):
    housing = Housing.query.get_or_404(housing_id)
    
    if housing.images:
        for image in housing.images.split(','):
            try:
                os.remove(os.path.join(app.config['UPLOAD_FOLDER'], image))
            except:
                pass
    
    db.session.delete(housing)
    db.session.commit()
    
    return jsonify({'success': True})

@app.route('/admin/applications')
@login_required
@admin_required
def admin_applications():
    individual_applications = Application.query.order_by(Application.created_at.desc()).all()
    group_applications = GroupApplication.query.order_by(GroupApplication.created_at.desc()).all()
    
    return render_template('admin_applications.html', 
                         individual_applications=individual_applications,
                         group_applications=group_applications)

@app.route('/admin/applications/<int:application_id>/<string:action>', methods=['POST'])
@login_required
@admin_required
def admin_handle_application(application_id, action):
    data = request.get_json()
    app_type = data.get('type', 'individual') if data else 'individual'
    
    if app_type == 'group':
        group_app = GroupApplication.query.get_or_404(application_id)
        
        if action == 'approve':
            group_app.status = 'approved'
            
            match = group_app.match_request
            for student_id in [match.sender_id, match.receiver_id]:
                notification = Notification(
                    user_id=student_id,
                    type='application_update',
                    title='Group Application Approved',
                    message=f'Your group application for {group_app.housing.title} has been approved!',
                    link='/applications'
                )
                db.session.add(notification)
            
            agreement = Agreement(
                student_id=match.sender_id,
                housing_id=group_app.housing_id,
                match_request_id=match.id,
                agreement_text=f"""
                ROOMMATE GROUP ACCOMMODATION AGREEMENT

                This agreement is made between:
                {match.sender.get_full_name()} and {match.receiver.get_full_name()} (collectively "Students")
                and the accommodation provider for the property at {group_app.housing.address}.

                PROPERTY DETAILS:
                - Address: {group_app.housing.address}
                - Monthly Rent: R{group_app.housing.price:,.0f}
                - Bedrooms: {group_app.housing.bedrooms}
                
                TERMS:
                1. Both students agree to share the accommodation
                2. Rent and utilities to be split equally between both students
                3. Both students are jointly responsible for the lease terms
                4. This agreement is binding upon acceptance by both parties

                Please review and confirm this agreement to proceed.
                """,
                status='pending'
            )
            db.session.add(agreement)
            
        elif action == 'reject':
            group_app.status = 'rejected'
            
            match = group_app.match_request
            for student_id in [match.sender_id, match.receiver_id]:
                notification = Notification(
                    user_id=student_id,
                    type='application_update',
                    title='Group Application Not Approved',
                    message=f'Your group application for {group_app.housing.title} was not approved.',
                    link='/applications'
                )
                db.session.add(notification)
        
        group_app.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True})
    
    else:
        application = Application.query.get_or_404(application_id)
        
        if action == 'approve':
            application.status = 'approved'
            
            notification = Notification(
                user_id=application.student_id,
                type='application_update',
                title='Application Approved',
                message=f'Your application for {application.housing.title} has been approved!',
                link='/applications'
            )
            db.session.add(notification)
            
            agreement = Agreement(
                student_id=application.student_id,
                housing_id=application.housing_id,
                agreement_text=f"""
                ROOMMATE ACCOMMODATION AGREEMENT
            
                This agreement is made between {application.student.get_full_name()} (Student) and 
                the accommodation provider for the property at {application.housing.address}.
            
                Property Details:
                - Address: {application.housing.address}
                - Monthly Rent: R{application.housing.price:,.0f}
                - Move-in Date: {application.move_in_date.strftime('%Y-%m-%d') if application.move_in_date else 'TBD'}
                - Lease Term: {application.lease_term if application.lease_term else 'Standard'}
            
                Terms and Conditions:
                1. The student agrees to pay rent on the first of each month
                2. The student agrees to maintain the property in good condition
                3. The student agrees to follow all building rules and regulations
                4. This agreement is binding upon acceptance
            
                Please review and confirm this agreement to proceed.
                """,
                status='pending'
            )
            db.session.add(agreement)
            
        elif action == 'reject':
            application.status = 'rejected'
            
            notification = Notification(
                user_id=application.student_id,
                type='application_update',
                title='Application Not Approved',
                message=f'Your application for {application.housing.title} was not approved at this time.',
                link='/applications'
            )
            db.session.add(notification)
        
        application.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({'success': True})

@app.route('/admin/matches')
@login_required
@admin_required
def admin_matches():
    matches = MatchRequest.query.filter_by(status='accepted').order_by(MatchRequest.updated_at.desc()).all()
    finalised = MatchRequest.query.filter_by(status='finalised').order_by(MatchRequest.finalised_at.desc()).all()
    return render_template('admin_matches.html', matches=matches, finalised=finalised)

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
        admin = User.query.filter_by(username='admin').first()
        if not admin:
            admin = User(
                username='admin',
                email='admin@example.com',
                first_name='Admin',
                last_name='User',
                role='admin'
            )
            admin.set_password('admin123')
            db.session.add(admin)
            db.session.commit()
            print("Admin user created - username: admin, password: admin123")
    
    app.run(debug=True)