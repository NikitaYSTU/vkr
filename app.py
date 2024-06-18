import json
import os
import re
import tempfile
import bcrypt
import psycopg2
from flask_wtf import FlaskForm
from wtforms.fields.simple import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from config import host, port, user, password, db_name
import nltk
import fitz
from flask import Flask, request, redirect, url_for, render_template, send_from_directory, flash, send_file, jsonify, \
    abort
from flask_login import LoginManager, login_user, login_required, logout_user, UserMixin, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.utils import secure_filename
from natasha import NamesExtractor, MorphVocab

UPLOAD_FOLDER = 'uploads'
ALLOWED_EXTENSIONS = {'pdf'}

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
uploaded_files = {}
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://username:password@localhost/yourdatabase'
app.config['UPLOAD_FOLDER'] = tempfile.gettempdir()
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

section_patterns = [
    r"ЛИЧНАЯ ИНФОРМАЦИЯ", r"ОПЫТ РАБОТЫ", r"ОБРАЗОВАНИЕ", r"КУРСЫ И ТРЕНИНГИ",
    r"ДОПОЛНИТЕЛЬНАЯ ИНФОРМАЦИЯ", r"КОНТАКТЫ", r"ЗНАНИЕ ЯЗЫКОВ",
    r"ДОСТИЖЕНИЯ", r"ОБО МНЕ", r"КЛЮЧЕВЫЕ НАВЫКИ", r"КОМПЬЮТЕРНЫЕ НАВЫКИ", r"НАВЫКИ"
]

section_regex = re.compile("|".join(section_patterns), re.IGNORECASE)

nltk.download('punkt')
nltk.download('maxent_ne_chunker')
nltk.download('words')

def get_db_connection():
    conn = psycopg2.connect(
        host=host,
        port=port,
        user=user,
        password=password,
        database=db_name,
    )
    return conn

class User(UserMixin):
    def __init__(self, user_id, username, user_email, user_password):
        self.id = user_id
        self.username = username
        self.user_email = user_email
        self.user_password = user_password

    @staticmethod
    def get(user_id):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE user_id = %s', (user_id,))
        user_data = cur.fetchone()
        cur.close()
        conn.close()
        if user_data:
            return User(user_id=user_data[0], username=user_data[1], user_email=user_data[2], user_password=user_data[3])
        return None

    @staticmethod
    def get_by_email(user_email):
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute('SELECT * FROM users WHERE user_email = %s', (user_email,))
        user_data = cur.fetchone()
        cur.close()
        conn.close()
        if user_data:
            return User(user_id=user_data[0], username=user_data[1], user_email=user_data[2], user_password=user_data[3])
        return None

class UserFile(db.Model):
    user_file_id = db.Column(db.Integer, primary_key=True)
    user_filename = db.Column(db.String(255), nullable=False)
    user_filepath = db.Column(db.String(255), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.user_id'), nullable=False)

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=150)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.get_by_email(form.email.data)
        if existing_user:
            flash('Пользователь с такой почтой уже зарегистрирован.', 'danger')
            return redirect(url_for('register'))

        hashed_password = bcrypt.hashpw(form.password.data.encode('utf-8'),
                                        bcrypt.gensalt())  # Хэширование пароля при регистрации
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute(
            'INSERT INTO users (username, user_email, user_password) VALUES (%s, %s, %s)',
            (form.username.data, form.email.data, hashed_password.decode('utf-8'))
        )
        conn.commit()
        cur.close()
        conn.close()
        flash('Ваш аккаунт был успешно создан!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.get_by_email(form.email.data)
        if user and bcrypt.checkpw(form.password.data.encode('utf-8'), user.user_password.encode('utf-8')):  # Проверка пароля при входе
            login_user(user, remember=True)
            return redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check email and password', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_pdf(pdf_path):
    text = ""
    with fitz.open(pdf_path) as doc:
        for page in doc:
            text += page.get_text()
    return text

def clean_text(text):
    text = re.sub(r'\.{2,}', '.', text)
    text = re.sub(r'(…+)', '', text)
    return text

def extract_names(text):
    morph_vocab = MorphVocab()
    extractor = NamesExtractor(morph_vocab)
    matches = extractor(text)
    names = [match.fact.first + " " + match.fact.last for match in matches if match.fact.first and match.fact.last]
    return names

def normalize_text(text):
    if isinstance(text, str):
        return re.sub(r'[^\w\s]', '', text).strip().lower()
    return ''

def split_into_blocks(text):
    lines = text.split('\n')
    blocks = []
    current_block = []
    current_section = None

    for line in lines:
        stripped_line = line.strip()
        if not stripped_line:
            continue

        normalized_line = normalize_text(stripped_line)

        if section_regex.match(normalized_line):
            if current_block:
                blocks.append((current_section, current_block))
                current_block = []

            current_section = stripped_line
        else:
            current_block.append(stripped_line)

    if current_block:
        blocks.append((current_section, current_block))

    return blocks

def split_into_subblocks(block):
    subblocks = []
    current_subblock = []
    current_subsection = None
    date_pattern = re.compile(r'\d{2}\.\d{4}-\d{2}\.\d{4}')

    def is_non_text_line(line):
        return not re.search(r'\w', line) and re.search(r'\W', line)

    def is_quote_unclosed(text):
        quote_count = text.count('«') + text.count('»')
        return quote_count % 2 != 0

    if block:
        for line_idx, line in enumerate(block):
            stripped_line = line.strip()

            if not stripped_line or is_non_text_line(stripped_line):
                continue

            if ':' in stripped_line and not date_pattern.match(stripped_line):
                if current_subblock:
                    subblocks.append((current_subsection, current_subblock))
                    current_subblock = []

                parts = stripped_line.split(':', 1)
                current_subsection = parts[0].strip()
                current_subblock.append(parts[1].strip())
            else:
                if date_pattern.match(stripped_line):
                    if current_subblock:
                        subblocks.append((current_subsection, current_subblock))
                    current_subsection = None
                    current_subblock = [stripped_line]

                else:
                    if current_subblock and (stripped_line[0].islower() or is_quote_unclosed(current_subblock[-1])):
                        current_subblock[-1] += " " + stripped_line
                    else:
                        current_subblock.append(stripped_line)

        if current_subblock:
            subblocks.append((current_subsection, current_subblock))

        if subblocks:
            for idx, (subsection, content) in enumerate(subblocks):
                try:
                    names = extract_names(" ".join(content))
                    if names:
                        subblocks[idx] = ("ФИО", content)
                        break
                except:
                    continue

            subblocks = [(subsection, content) for subsection, content in subblocks if not (subsection == "Контактная информация" and all(item == "" for item in content))]
            subblocks = [(subsection, content) for subsection, content in subblocks if not (subsection is None and all(item == "" for item in content))]

    return subblocks

def process_text(text, sections=None):
    blocks = split_into_blocks(text)
    result = {}
    contact_info_found = False

    if not sections:
        for section, content in blocks:
            subblocks = split_into_subblocks(content)

            names = extract_names(" ".join(content))
            if names:
                section = "Контактная информация"
                contact_info_found = True

            result[section] = subblocks
    else:
        normalized_sections = [normalize_text(section) for section in sections]

        for section, content in blocks:
            normalized_section = normalize_text(section)
            subblocks = split_into_subblocks(content)

            names = extract_names(" ".join(content))
            if names:
                result["Контактная информация"] = subblocks
                contact_info_found = True

            if normalized_section in normalized_sections:
                result[section] = subblocks

        if contact_info_found and "Контактная информация" not in sections:
            sections.append("Контактная информация")

    return result

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)

        file = request.files['file']
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)

        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)

            text = extract_text_from_pdf(file_path)
            text = clean_text(text)
            sections = request.form.get('sections')
            if sections:
                sections = sections.split(',')
            processed_text = process_text(text, sections)

            json_filename = filename.rsplit('.', 1)[0] + '.json'
            json_file_path = os.path.join(app.config['UPLOAD_FOLDER'], json_filename)
            with open(json_file_path, 'w', encoding='utf-8') as json_file:
                json.dump(processed_text, json_file, ensure_ascii=False)

            save_to_db = request.values.get('save_to_database')
            save_to_db = save_to_db == 'true'

            if current_user.is_authenticated and save_to_db:
                save_file_to_database(json_filename, json_file_path, current_user.id)

            return jsonify({'json_filename': json_filename})

    return render_template('index.html')

def save_file_to_database(filename, filepath, user_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        'INSERT INTO user_file (user_filename, user_filepath, user_id) VALUES (%s, %s, %s)',
        (filename, filepath, user_id)
    )
    conn.commit()
    cursor.close()
    conn.close()

@app.route('/profile')
@login_required
def profile():
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute('SELECT * FROM user_file WHERE user_id = %s', (current_user.id,))
    saved_files = cur.fetchall()
    cur.close()
    conn.close()
    return render_template('profile.html', user=current_user, saved_files=saved_files)

@app.route('/download_saved_file/<int:file_id>')
@login_required
def download_saved_file(file_id):
    conn = get_db_connection()
    cur = conn.cursor()
    cur.execute("SELECT user_filepath, user_id FROM user_file WHERE user_file_id = %s", (file_id,))
    saved_file = cur.fetchone()
    cur.close()
    conn.close()

    if not saved_file:
        abort(404)

    saved_filepath, user_id = saved_file

    if user_id != current_user.id:
        abort(403)

    return send_file(saved_filepath, as_attachment=True)

@app.route('/download/<filename>')
def download_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename, as_attachment=True)


@app.route('/delete_saved_file/<int:file_id>', methods=['POST'])
@login_required
def delete_saved_file(file_id):
    if request.method == 'POST':
        conn = get_db_connection()
        cur = conn.cursor()
        cur.execute("SELECT user_id FROM user_file WHERE user_file_id = %s", (file_id,))
        user_id = cur.fetchone()
        if not user_id or user_id[0] != current_user.id:
            abort(403)
        cur.execute("DELETE FROM user_file WHERE user_file_id = %s", (file_id,))
        conn.commit()
        cur.close()
        conn.close()
        flash('Файл успешно удален', 'success')
    else:
        abort(405)
    return redirect(url_for('profile'))

if __name__ == '__main__':
    app.run(debug=True)