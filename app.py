from flask import Flask, jsonify, request, send_from_directory, render_template
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import datetime
import os

app = Flask(__name__)
CORS(app)

# Set up static file serving
@app.route('/')
def index():
    return send_from_directory('.', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('.', path)

# Setup the Flask-JWT-Extended extension
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', 'dev-secret-key')  # Change this in production!
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = datetime.timedelta(hours=1)
jwt = JWTManager(app)

# Database initialization
def init_db():
    conn = sqlite3.connect('exam_app.db')
    c = conn.cursor()
    
    # Create users table
    c.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        email TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        role TEXT NOT NULL,
        approved BOOLEAN DEFAULT 1
    )
    ''')
    
    # Create subjects table
    c.execute('''
    CREATE TABLE IF NOT EXISTS subjects (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL UNIQUE,
        description TEXT
    )
    ''')
    
    # Create exams table
    c.execute('''
    CREATE TABLE IF NOT EXISTS exams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        title TEXT NOT NULL,
        subject_id INTEGER,
        description TEXT,
        duration INTEGER NOT NULL,
        scheduled_date TEXT,
        scheduled_time TEXT,
        created_by INTEGER,
        FOREIGN KEY (subject_id) REFERENCES subjects(id),
        FOREIGN KEY (created_by) REFERENCES users(id)
    )
    ''')
    
    # Create questions table
    c.execute('''
    CREATE TABLE IF NOT EXISTS questions (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        exam_id INTEGER,
        question_text TEXT NOT NULL,
        question_type TEXT NOT NULL,
        marks INTEGER DEFAULT 1,
        FOREIGN KEY (exam_id) REFERENCES exams(id)
    )
    ''')
    
    # Create options table for multiple choice questions
    c.execute('''
    CREATE TABLE IF NOT EXISTS options (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        question_id INTEGER,
        option_text TEXT NOT NULL,
        is_correct BOOLEAN,
        FOREIGN KEY (question_id) REFERENCES questions(id)
    )
    ''')
    
    # Create user_exams table to track exam attempts
    c.execute('''
    CREATE TABLE IF NOT EXISTS user_exams (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        exam_id INTEGER,
        start_time TEXT,
        end_time TEXT,
        score REAL,
        status TEXT DEFAULT 'not_started',
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (exam_id) REFERENCES exams(id)
    )
    ''')
    
    # Create user_answers table
    c.execute('''
    CREATE TABLE IF NOT EXISTS user_answers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_exam_id INTEGER,
        question_id INTEGER,
        answer_text TEXT,
        selected_option_id INTEGER,
        is_correct BOOLEAN,
        feedback TEXT,
        FOREIGN KEY (user_exam_id) REFERENCES user_exams(id),
        FOREIGN KEY (question_id) REFERENCES questions(id),
        FOREIGN KEY (selected_option_id) REFERENCES options(id)
    )
    ''')
    
    # Insert default admin user if not exists
    c.execute("SELECT * FROM users WHERE username = 'admin'")
    if not c.fetchone():
        admin_password = generate_password_hash('admin123')
        c.execute("INSERT INTO users (username, email, password, role, approved) VALUES (?, ?, ?, ?, ?)",
                  ('admin', 'admin@example.com', admin_password, 'admin', 1))
    
    # Insert some sample subjects if not exists
    for subject in ['Mathematics', 'Science', 'English', 'History']:
        c.execute("SELECT * FROM subjects WHERE name = ?", (subject,))
        if not c.fetchone():
            c.execute("INSERT INTO subjects (name, description) VALUES (?, ?)",
                     (subject, f'Sample {subject} subject for mock tests'))
    
    conn.commit()
    conn.close()

# Initialize the database
init_db()

# Helper function to get database connection
def get_db_connection():
    conn = sqlite3.connect('exam_app.db')
    conn.row_factory = sqlite3.Row
    return conn

# Auth routes
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    
    # Validate required fields
    required_fields = ['username', 'email', 'password']
    for field in required_fields:
        if field not in data or not data[field]:
            return jsonify({'error': f'{field} is required'}), 400
    
    conn = get_db_connection()
    try:
        # Check if username or email already exists
        user = conn.execute('SELECT * FROM users WHERE username = ? OR email = ?', 
                          (data['username'], data['email'])).fetchone()
        if user:
            return jsonify({'error': 'Username or email already exists'}), 400
        
        # Hash the password
        hashed_password = generate_password_hash(data['password'])
        
        # Set role to 'student' by default
        role = data.get('role', 'student')
        
        # Students need approval, admins are approved by default (for simplicity)
        approved = 1 if role == 'admin'  else 0
        # Insert new user
        conn.execute('INSERT INTO users (username, email, password, role, approved) VALUES (?, ?, ?, ?, ?)',
                   (data['username'], data['email'], hashed_password, role, approved))
        conn.commit()
        
        return jsonify({'message': 'User registered successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({'error': 'Username and password are required'}), 400
    
    conn = get_db_connection()
    try:
        user = conn.execute('SELECT * FROM users WHERE username = ?', (data['username'],)).fetchone()
        
        if not user or not check_password_hash(user['password'], data['password']):
            return jsonify({'error': 'Invalid username or password'}), 401
        
        if not user['approved'] and user['role'] == 'student':
            return jsonify({'error': 'Your account is pending approval'}), 403
        
        # Create access token
        access_token = create_access_token(identity={
            'user_id': user['id'],
            'username': user['username'],
            'role': user['role']
        })
        
        return jsonify({
            'message': 'Login successful',
            'access_token': access_token,
            'user': {
                'id': user['id'],
                'username': user['username'],
                'email': user['email'],
                'role': user['role']
            }
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# Protected routes
@app.route('/api/profile', methods=['GET'])
@jwt_required()
def get_profile():
    current_user = get_jwt_identity()
    return jsonify(current_user), 200

# Admin routes
@app.route('/api/admin/users', methods=['GET'])
@jwt_required()
def get_users():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Unauthorized access'}), 403
    
    conn = get_db_connection()
    try:
        users = conn.execute('SELECT id, username, email, role, approved FROM users').fetchall()
        return jsonify([dict(user) for user in users]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/admin/users/<int:user_id>/approve', methods=['PUT'])
@jwt_required()
def approve_user(user_id):
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Unauthorized access'}), 403
    
    conn = get_db_connection()
    try:
        conn.execute('UPDATE users SET approved = 1 WHERE id = ?', (user_id,))
        conn.commit()
        return jsonify({'message': 'User approved successfully'}), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/admin/subjects', methods=['GET', 'POST'])
@jwt_required()
def manage_subjects():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Unauthorized access'}), 403
    
    conn = get_db_connection()
    try:
        if request.method == 'GET':
            subjects = conn.execute('SELECT * FROM subjects').fetchall()
            return jsonify([dict(subject) for subject in subjects]), 200
        else:  # POST
            data = request.get_json()
            if not data or not data.get('name'):
                return jsonify({'error': 'Subject name is required'}), 400
            
            conn.execute('INSERT INTO subjects (name, description) VALUES (?, ?)',
                       (data['name'], data.get('description', '')))
            conn.commit()
            return jsonify({'message': 'Subject created successfully'}), 201
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/admin/exams', methods=['POST'])
@jwt_required()
def create_exam():
    current_user = get_jwt_identity()
    if current_user['role'] != 'admin':
        return jsonify({'error': 'Unauthorized access'}), 403
    
    data = request.get_json()
    required_fields = ['title', 'subject_id', 'duration', 'questions']
    for field in required_fields:
        if field not in data:
            return jsonify({'error': f'{field} is required'}), 400
    
    conn = get_db_connection()
    try:
        # Create exam
        cur = conn.cursor()
        cur.execute('''
        INSERT INTO exams (title, subject_id, description, duration, scheduled_date, scheduled_time, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?)
        ''', (
            data['title'],
            data['subject_id'],
            data.get('description', ''),
            data['duration'],
            data.get('scheduled_date', None),
            data.get('scheduled_time', None),
            current_user['user_id']
        ))
        exam_id = cur.lastrowid
        
        # Add questions
        for q in data['questions']:
            cur.execute('''
            INSERT INTO questions (exam_id, question_text, question_type, marks)
            VALUES (?, ?, ?, ?)
            ''', (
                exam_id,
                q['question_text'],
                q['question_type'],
                q.get('marks', 1)
            ))
            question_id = cur.lastrowid
            
            # Add options for multiple choice questions
            if q['question_type'] == 'multiple_choice' and 'options' in q:
                for opt in q['options']:
                    cur.execute('''
                    INSERT INTO options (question_id, option_text, is_correct)
                    VALUES (?, ?, ?)
                    ''', (
                        question_id,
                        opt['option_text'],
                        opt.get('is_correct', False)
                    ))
        
        conn.commit()
        return jsonify({'message': 'Exam created successfully', 'exam_id': exam_id}), 201
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

# Student routes
@app.route('/api/subjects', methods=['GET'])
@jwt_required()
def get_subjects():
    conn = get_db_connection()
    try:
        subjects = conn.execute('SELECT * FROM subjects').fetchall()
        return jsonify([dict(subject) for subject in subjects]), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/exams', methods=['GET'])
@jwt_required()
def get_exams():
    current_user = get_jwt_identity()
    
    conn = get_db_connection()
    try:
        # Get all available exams with subject info
        exams = conn.execute('''
        SELECT e.*, s.name as subject_name 
        FROM exams e
        JOIN subjects s ON e.subject_id = s.id
        ORDER BY 
            CASE 
                WHEN e.scheduled_date IS NULL THEN 1
                ELSE 0
            END,
            e.scheduled_date ASC,
            e.scheduled_time ASC
        ''').fetchall()
        
        # Get user's exam attempts
        user_exams = conn.execute('''
        SELECT user_exam_id, exam_id, status, score 
        FROM user_exams 
        WHERE user_id = ?
        ''', (current_user['user_id'],)).fetchall()
        
        user_exam_map = {ue['exam_id']: dict(ue) for ue in user_exams}
        
        result = []
        for exam in exams:
            exam_dict = dict(exam)
            exam_dict['user_status'] = user_exam_map.get(exam['id'], {}).get('status', 'not_started')
            exam_dict['user_score'] = user_exam_map.get(exam['id'], {}).get('score', None)
            result.append(exam_dict)
        
        return jsonify(result), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/exams/<int:exam_id>', methods=['GET'])
@jwt_required()
def get_exam_details(exam_id):
    current_user = get_jwt_identity()
    
    conn = get_db_connection()
    try:
        # Get exam details
        exam = conn.execute('''
        SELECT e.*, s.name as subject_name 
        FROM exams e
        JOIN subjects s ON e.subject_id = s.id
        WHERE e.id = ?
        ''', (exam_id,)).fetchone()
        
        if not exam:
            return jsonify({'error': 'Exam not found'}), 404
        
        # Check if user has already started this exam
        user_exam = conn.execute('''
        SELECT * FROM user_exams 
        WHERE user_id = ? AND exam_id = ?
        ''', (current_user['user_id'], exam_id)).fetchone()
        
        exam_dict = dict(exam)
        exam_dict['user_exam_status'] = dict(user_exam) if user_exam else None
        
        # Only include questions if the exam is 'in_progress'
        if user_exam and user_exam['status'] == 'in_progress':
            questions = conn.execute('''
            SELECT q.* FROM questions q
            WHERE q.exam_id = ?
            ''', (exam_id,)).fetchall()
            
            questions_list = []
            for q in questions:
                q_dict = dict(q)
                if q['question_type'] == 'multiple_choice':
                    options = conn.execute('''
                    SELECT id, option_text FROM options
                    WHERE question_id = ?
                    ''', (q['id'],)).fetchall()
                    q_dict['options'] = [dict(opt) for opt in options]
                
                # Get user's answer if any
                user_answer = conn.execute('''
                SELECT * FROM user_answers
                WHERE user_exam_id = ? AND question_id = ?
                ''', (user_exam['id'], q['id'])).fetchone()
                
                if user_answer:
                    q_dict['user_answer'] = dict(user_answer)
                
                questions_list.append(q_dict)
            
            exam_dict['questions'] = questions_list
        
        return jsonify(exam_dict), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/exams/<int:exam_id>/start', methods=['POST'])
@jwt_required()
def start_exam(exam_id):
    current_user = get_jwt_identity()
    
    conn = get_db_connection()
    try:
        # Check if the exam exists
        exam = conn.execute('SELECT * FROM exams WHERE id = ?', (exam_id,)).fetchone()
        if not exam:
            return jsonify({'error': 'Exam not found'}), 404
        
        # Check if user has already started or completed this exam
        user_exam = conn.execute('''
        SELECT * FROM user_exams 
        WHERE user_id = ? AND exam_id = ?
        ''', (current_user['user_id'], exam_id)).fetchone()
        
        if user_exam and user_exam['status'] in ['in_progress', 'completed']:
            return jsonify({'error': f'Exam already {user_exam["status"]}'}), 400
        
        # Create new exam attempt
        now = datetime.datetime.now().isoformat()
        cursor = conn.cursor()
        cursor.execute('''
        INSERT INTO user_exams (user_id, exam_id, start_time, status)
        VALUES (?, ?, ?, 'in_progress')
        ''', (current_user['user_id'], exam_id, now))
        user_exam_id = cursor.lastrowid
        
        conn.commit()
        return jsonify({
            'message': 'Exam started successfully',
            'user_exam_id': user_exam_id,
            'start_time': now
        }), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/exams/<int:exam_id>/submit', methods=['POST'])
@jwt_required()
def submit_exam(exam_id):
    current_user = get_jwt_identity()
    data = request.get_json()
    
    if not data or 'answers' not in data:
        return jsonify({'error': 'Answers are required'}), 400
    
    conn = get_db_connection()
    try:
        # Get user exam
        user_exam = conn.execute('''
        SELECT * FROM user_exams 
        WHERE user_id = ? AND exam_id = ? AND status = 'in_progress'
        ''', (current_user['user_id'], exam_id)).fetchone()
        
        if not user_exam:
            return jsonify({'error': 'No active exam found'}), 404
        
        cursor = conn.cursor()
        total_questions = 0
        correct_answers = 0
        
        # Process each answer
        for answer in data['answers']:
            question_id = answer['question_id']
            question = conn.execute('SELECT * FROM questions WHERE id = ?', (question_id,)).fetchone()
            
            if not question:
                continue
            
            total_questions += 1
            is_correct = False
            
            if question['question_type'] == 'multiple_choice':
                selected_option_id = answer.get('selected_option_id')
                if selected_option_id:
                    # Check if the selected option is correct
                    option = conn.execute('''
                    SELECT is_correct FROM options 
                    WHERE id = ? AND question_id = ?
                    ''', (selected_option_id, question_id)).fetchone()
                    
                    if option and option['is_correct']:
                        is_correct = True
                        correct_answers += 1
                
                cursor.execute('''
                INSERT INTO user_answers (user_exam_id, question_id, selected_option_id, is_correct)
                VALUES (?, ?, ?, ?)
                ''', (user_exam['id'], question_id, selected_option_id, is_correct))
            
            else:  # Open-ended question
                answer_text = answer.get('answer_text', '')
                cursor.execute('''
                INSERT INTO user_answers (user_exam_id, question_id, answer_text, is_correct)
                VALUES (?, ?, ?, ?)
                ''', (user_exam['id'], question_id, answer_text, False))  # Initially marked as incorrect until reviewed
        
        # Calculate score for multiple choice questions (open-ended will be graded by admin)
        score = (correct_answers / total_questions * 100) if total_questions > 0 else 0
        
        # Update user exam status
        now = datetime.datetime.now().isoformat()
        cursor.execute('''
        UPDATE user_exams 
        SET status = 'completed', end_time = ?, score = ?
        WHERE id = ?
        ''', (now, score, user_exam['id']))
        
        conn.commit()
        
        return jsonify({
            'message': 'Exam submitted successfully',
            'score': score,
            'total_questions': total_questions,
            'correct_answers': correct_answers
        }), 200
    except Exception as e:
        conn.rollback()
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

@app.route('/api/dashboard', methods=['GET'])
@jwt_required()
def get_dashboard_data():
    current_user = get_jwt_identity()
    
    conn = get_db_connection()
    try:
        # Get upcoming exams
        upcoming_exams = conn.execute('''
        SELECT e.*, s.name as subject_name 
        FROM exams e
        JOIN subjects s ON e.subject_id = s.id
        WHERE e.scheduled_date >= date('now')
        ORDER BY e.scheduled_date ASC, e.scheduled_time ASC
        LIMIT 5
        ''').fetchall()
        
        # Get recent exam results
        recent_results = conn.execute('''
        SELECT ue.*, e.title, e.duration, s.name as subject_name
        FROM user_exams ue
        JOIN exams e ON ue.exam_id = e.id
        JOIN subjects s ON e.subject_id = s.id
        WHERE ue.user_id = ? AND ue.status = 'completed'
        ORDER BY ue.end_time DESC
        LIMIT 5
        ''', (current_user['user_id'],)).fetchall()
        
        # Get performance by subject
        subject_performance = conn.execute('''
        SELECT s.name, AVG(ue.score) as average_score, COUNT(ue.id) as exams_taken
        FROM user_exams ue
        JOIN exams e ON ue.exam_id = e.id
        JOIN subjects s ON e.subject_id = s.id
        WHERE ue.user_id = ? AND ue.status = 'completed'
        GROUP BY s.id
        ''', (current_user['user_id'],)).fetchall()
        
        return jsonify({
            'upcoming_exams': [dict(exam) for exam in upcoming_exams],
            'recent_results': [dict(result) for result in recent_results],
            'subject_performance': [dict(perf) for perf in subject_performance]
        }), 200
    except Exception as e:
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    app.run(debug=True)
    