# CertifyEasy - Qbank Web App (Flask)
import csv
import random
import os
import json
from flask import Flask, render_template, request, jsonify, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
import bcrypt

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()  # Random secure key

# Database setup
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///certifyeasy.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Login manager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# User model
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(120), nullable=False)

# Progress model
class Progress(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    completed_questions = db.Column(db.Integer, default=0)
    total_questions = db.Column(db.Integer, default=0)

# WrongAnswers model - NEW
class WrongAnswers(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    subject = db.Column(db.String(100), nullable=False)
    question_text = db.Column(db.String(500), nullable=False)
    correct_answer = db.Column(db.String(100), nullable=False)
    options = db.Column(db.String(500), nullable=False)  # Store as JSON string

# CIA Part 1 Subjects
SUBJECTS = {
    "1": "Foundations of Internal Auditing",
    "2": "Independence and Objectivity",
    "3": "Proficiency and Due Professional Care",
    "4": "Quality Assurance and Improvement Program",
    "5": "Governance, Risk Management, and Control",
    "6": "Fraud Risks"
}

# Load Qbank from CSV
def load_qbank(file_path):
    qbank_by_subject = {subject: [] for subject in SUBJECTS.values()}
    encodings = ['utf-8', 'latin1', 'windows-1252']
    for encoding in encodings:
        try:
            with open(file_path, newline='', encoding=encoding) as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    subject = row["subject"]
                    if subject in qbank_by_subject:
                        qbank_by_subject[subject].append({
                            "question": row["question"],
                            "options": [row["option1"], row["option2"], row["option3"], row["option4"]],
                            "answer": row["answer"],
                            "explanation": row["explanation"]
                        })
            return qbank_by_subject
        except Exception as e:
            print(f"Error loading Qbank with {encoding}: {e}")
    return {}

# File paths
file_path = r"C:\Users\a.merini\Desktop\CertifyEasy AI\QBANK_CIA1.csv"
qbank = load_qbank(file_path)
sessions = {}

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def root():
    if current_user.is_authenticated:
        progress = {p.subject: p.completed_questions / p.total_questions * 100 if p.total_questions > 0 else 0 
                    for p in Progress.query.filter_by(user_id=current_user.id).all()}
        return render_template('index.html', subjects=SUBJECTS, progress=progress, username=current_user.username)
    return redirect(url_for('home'))

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if len(password) < 6:
            flash('Password must be at least 6 characters.')
            return redirect(url_for('signup'))
        if User.query.filter_by(username=username).first():
            flash('Username already exists.')
            return redirect(url_for('signup'))
        hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        user = User(username=username, password_hash=hashed)
        db.session.add(user)
        db.session.commit()
        login_user(user)
        return redirect(url_for('root'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password_hash):
            login_user(user)
            return redirect(url_for('root'))
        flash('Invalid username or password.')
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/start', methods=['POST'])
@login_required
def start():
    subject = request.form['subject']
    print(f"Starting practice for subject: {subject}")
    if subject not in qbank or not qbank[subject]:
        return jsonify({"error": f"No questions available for {subject}."}), 400
    
    prog = Progress.query.filter_by(user_id=current_user.id, subject=subject).first()
    if not prog:
        prog = Progress(user_id=current_user.id, subject=subject, total_questions=len(qbank[subject]))
        db.session.add(prog)
        db.session.commit()
    
    session_data = {
        "subject": subject,
        "qbank": qbank[subject].copy(),
        "current_qbank_index": 0,
        "wrong_answers": [],  # Temp storage for this session
        "next_question": None,
        "total": len(qbank[subject]),
        "correct_streak": 0,
        "mastery_correct": prog.completed_questions,
        "mastery_total": prog.total_questions,
        "longest_streak": 0,
        "explanations": [],
        "repeat_phase": False  # Tracks if we're in repeat mode
    }
    random.shuffle(session_data["qbank"])
    session_data["next_question"] = session_data["qbank"][0]
    sessions[current_user.id] = session_data
    mastery_percentage = (session_data["mastery_correct"] / session_data["mastery_total"] * 100) if session_data["mastery_total"] > 0 else 0
    return jsonify({
        "subject": subject,
        "question": session_data["next_question"],
        "index": 0,
        "total": session_data["total"],
        "mastery_percentage": mastery_percentage,
        "correct_streak": 0,
        "message": ""
    })

@app.route('/answer', methods=['POST'])
@login_required
def answer():
    try:
        subject = request.form.get('subject')
        user_answer = request.form.get('answer')
        index = int(request.form.get('index', 0))
        question_json = request.form.get('question', '{}')
        
        print(f"Received question_json: {question_json}")  # Debug log
        
        if not subject or subject not in qbank:
            return jsonify({"error": "Invalid or missing subject"}), 400
        if not user_answer:
            return jsonify({"error": "No answer provided"}), 400
        
        # Parse question JSON, handle empty/invalid cases
        try:
            question = json.loads(question_json) if question_json else {}
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            return jsonify({"error": "Invalid question data"}), 400
        
        if not question or "question" not in question:
            return jsonify({"error": "Missing question data"}), 400
        
        session = sessions.get(current_user.id)
        user_answer_idx = int(user_answer) - 1
        correct_answer = question["answer"]
        user_answer_text = question["options"][user_answer_idx]

        feedback = {
            "correct": user_answer_text == correct_answer,
            "user_answer": f"{chr(65 + user_answer_idx)}) {user_answer_text}",
            "correct_answer": f"{chr(65 + question['options'].index(correct_answer))} {correct_answer}",
            "explanation": question["explanation"]
        }
        
        if feedback["correct"]:
            session["mastery_correct"] += 1
            session["correct_streak"] += 1
            prog = Progress.query.filter_by(user_id=current_user.id, subject=subject).first()
            prog.completed_questions += 1
            db.session.commit()
        else:
            session["correct_streak"] = 0
            session["wrong_answers"].append({
                "question": question["question"],
                "options": question["options"],
                "answer": correct_answer,
                "explanation": question["explanation"]
            })
            wrong = WrongAnswers(
                user_id=current_user.id,
                subject=subject,
                question_text=question["question"],
                correct_answer=correct_answer,
                options=json.dumps(question["options"])
            )
            db.session.add(wrong)
            db.session.commit()
        
        session["current_qbank_index"] += 1
        
        if session["current_qbank_index"] >= len(session["qbank"]) and not session["repeat_phase"]:
            if session["wrong_answers"]:
                session["qbank"] = session["wrong_answers"].copy()
                session["wrong_answers"] = []
                session["current_qbank_index"] = 0
                session["repeat_phase"] = True
                next_q = session["qbank"][0]
                options = next_q["options"].copy()
                random.shuffle(options)
                next_q["options"] = options
                session["next_question"] = next_q
                mastery_percentage = (session["mastery_correct"] / session["mastery_total"] * 100) if session["mastery_total"] > 0 else 0
                return jsonify({
                    "subject": subject,
                    "feedback": feedback,
                    "next_question": session["next_question"],
                    "index": session["current_qbank_index"],
                    "total": session["mastery_total"],
                    "mastery_percentage": mastery_percentage,
                    "correct_streak": session["correct_streak"],
                    "message": "Now reviewing your weak spots!"
                })
            else:
                mastery_percentage = (session["mastery_correct"] / session["mastery_total"] * 100) if session["mastery_total"] > 0 else 0
                return jsonify({
                    "subject": subject,
                    "feedback": feedback,
                    "finished": True,
                    "wrong_count": 0,
                    "correct_count": session["mastery_correct"],
                    "total": session["mastery_total"],
                    "mastery_percentage": mastery_percentage,
                    "longest_streak": session["longest_streak"]
                })
        
        if session["current_qbank_index"] < len(session["qbank"]):
            next_q = session["qbank"][session["current_qbank_index"]]
            options = next_q["options"].copy()
            random.shuffle(options)
            next_q["options"] = options
            session["next_question"] = next_q
            mastery_percentage = (session["mastery_correct"] / session["mastery_total"] * 100) if session["mastery_total"] > 0 else 0
            return jsonify({
                "subject": subject,
                "feedback": feedback,
                "next_question": session["next_question"],
                "index": session["current_qbank_index"],
                "total": session["mastery_total"],
                "mastery_percentage": mastery_percentage,
                "correct_streak": session["correct_streak"]
            })
        else:
            mastery_percentage = (session["mastery_correct"] / session["mastery_total"] * 100) if session["mastery_total"] > 0 else 0
            return jsonify({
                "subject": subject,
                "feedback": feedback,
                "finished": True,
                "wrong_count": len(session["wrong_answers"]),
                "correct_count": session["mastery_correct"],
                "total": session["mastery_total"],
                "mastery_percentage": mastery_percentage,
                "longest_streak": session["longest_streak"]
            })
    except Exception as e:
        print(f"Error in /answer: {str(e)}")
        return jsonify({"error": f"Server error: {str(e)}"}), 500

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(debug=True)