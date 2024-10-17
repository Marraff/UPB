from flask import Flask, render_template, redirect, url_for, flash, jsonify
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import InputRequired, EqualTo
from flask_login import login_required, LoginManager, UserMixin, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
import re
import os
import hashlib
import hmac

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///data.db'
app.config['SECRET_KEY'] = 'upb'

db = SQLAlchemy(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Constants
SALT_LENGTH = 16  # Length of the salt (in bytes)
ITERATIONS = 100000  # Number of hashing iterations

'''
    Tabulka pre pouzivatelov:
    - id: jedinecne id pouzivatela
    - username: meno pouzivatela

    TODO: tabulku je treba doimplementovat
'''
class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)  # Storing hash as a string
    salt = db.Column(db.String(32), nullable=False)  # Salt is stored as a hex string

    def __repr__(self):
        return f'<User {self.username}>'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
    
with app.app_context():
    db.create_all()
    
    #test_user = User(username='test', password='test')
    #db.session.add(test_user)
    #db.session.commit()


class LoginForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    submit = SubmitField('Login')


class RegisterForm(FlaskForm):
    username = StringField('Username', validators=[InputRequired()])
    password = PasswordField('Password', validators=[InputRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[InputRequired(), EqualTo('password')])
    submit = SubmitField('Register')

# bod 2

def generate_salt():
    #Generate a random salt for each user.
    return os.urandom(SALT_LENGTH)

def hash_password(password, salt):
    """
    Securely hash the password with a salt using iterative SHA-256.
    
    :param password: The plain text password.
    :param salt: The salt value (binary).
    :return: The final hash (binary).
    """
    password = password.encode('utf-8')  # Convert password to bytes
    # Use HMAC for security (keyed hashing)
    hashed = hmac.new(salt, password, hashlib.sha256).digest()
    
    # Apply iterative hashing
    for i in range(ITERATIONS):
        hashed = hmac.new(salt, hashed, hashlib.sha256).digest()
    
    return hashed

def store_user_password(username, password):
    """Store a new user with a securely hashed password."""
    # Generate salt for this user
    salt = generate_salt()
    
    # Hash the password using the salt
    hashed_password = hash_password(password, salt)
    
    # Convert salt and hashed password to a format that can be stored (e.g., hexadecimal)
    salt_hex = salt.hex()
    hashed_password_hex = hashed_password.hex()

    # Create a new user record with the username, salt, and hashed password
    test_user = User(username=username, password=hashed_password_hex, salt=salt_hex)
    
    # Save the user to the database
    db.session.add(test_user)
    db.session.commit()

def verify_password(stored_hash, stored_salt, entered_password):
    #Verify a password by comparing it with the stored hash.
    # Convert the stored salt back to binary
    salt = bytes.fromhex(stored_salt)
    
    # Hash the entered password using the stored salt
    entered_hash = hash_password(entered_password, salt)
    
    # Convert both the stored hash and entered hash to hexadecimal for comparison
    return hmac.compare_digest(stored_hash, entered_hash.hex())

# bod 1

def validate_password_complexity(password):
    # Minimum length of 8 characters
    if len(password) < 8:
        flash("Password must be at least 8 characters long.", "danger")
        return False

    # At least one uppercase letter
    if not re.search(r'[A-Z]', password):
        flash("Password must contain at least one uppercase letter.", "danger")
        return False

    # At least one lowercase letter
    if not re.search(r'[a-z]', password):
        flash("Password must contain at least one lowercase letter.", "danger")
        return False

    # At least one digit
    if not re.search(r'\d', password):
        flash("Password must contain at least one digit.", "danger")
        return False

    # At least one special character
    if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
        flash("Password must contain at least one special character: !@#$%^&*(),.?\":{}|<> ", "danger")
        return False

    return True


@app.route('/')
@login_required
def home():
    return render_template('home.html', username=current_user.username)

@app.route('/login', methods=['GET', 'POST'])
def login():
    '''
        User login route.
    '''

    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # Fetch the user from the database by username
        user = User.query.filter_by(username=username).first()

        # Check if user exists
        if user and verify_password(user.password, user.salt, password):
            # If password is correct, log the user in
            login_user(user)
            return redirect(url_for('home'))

        # Flash an error message if the credentials are invalid
        flash('Invalid username or password.', 'danger')

    return render_template('login.html', form=form)


@app.route('/register', methods=['GET', 'POST'])
def register():
    '''
        Register a new user with secure password storage.
    '''

    form = RegisterForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        
        # Check if password meets complexity requirements
        if not validate_password_complexity(password):
            return render_template('register.html', form=form)

        # Generate salt and hash the password
        salt = generate_salt()  # Generate a new salt for this user
        hashed_password = hash_password(password, salt)  # Hash the password with the salt

        # Convert salt and hashed password to hex for storage
        salt_hex = salt.hex()
        hashed_password_hex = hashed_password.hex()

        # Create a new user with hashed password and salt
        test_user = User(username=username, password=hashed_password_hex, salt=salt_hex)
        
        # Add the user to the database
        db.session.add(test_user)
        db.session.commit()

        # Optionally, flash a success message
        flash('You have successfully registered!', 'success')

        return redirect(url_for('login'))

    return render_template('register.html', form=form)


@app.route('/show-users', methods=['GET'])
def show_users():
    users = User.query.all()  # Fetch all users from the database

    # Create a list of dictionaries representing each user
    users_list = []
    for user in users:
        user_data = {
            'id': user.id,
            'username': user.username,
            'password': user.password,
            'salt': user.salt
        }
        users_list.append(user_data)

    # Return the list as a JSON response
    return jsonify(users_list)

@login_required
@app.route('/logout', methods=['POST'])
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(port=1337)