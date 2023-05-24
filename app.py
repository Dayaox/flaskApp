from flask import Flask, render_template, redirect, url_for, request, flash, abort, session
from flask_login import LoginManager, login_user, current_user, login_required, logout_user, UserMixin
from functools import update_wrapper
from flask_mysqldb import MySQL
from werkzeug.security import check_password_hash
from flask_session import Session
from datetime import datetime, timedelta

app = Flask(__name__)
app.config['SECRET_KEY'] = 'mysecretkey'
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '39023902'
app.config['MYSQL_DB'] = 'ventas_flask'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)
app.config['SESSION_COOKIE_SECURE'] = True
Session(app)
mysql = MySQL(app)

login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin):
    def __init__(self, id, username, password, role, active=True):
        self.id = id
        self.username = username
        self.password = password
        self.role = role
        self.is_active = active

    def get_id(self):
        return str(self.id)

    def is_active(self):
        return self.active

    @staticmethod
    def get(user_id):
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE id = %s', (user_id,))
        user_data = cursor.fetchone()
        if user_data is None:
            return None
        user = User(*user_data)
        print(user_data)
        return user



@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@app.before_request
def before_request():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=30)
    session.modified = True
    if current_user.is_authenticated:
        last_active = session.get('last_active')
        if last_active is not None and (datetime.utcnow() - last_active) > timedelta(minutes=30):
            session.clear()
            return redirect(url_for('login'))
        session['last_active'] = datetime.utcnow()

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        print('acceso')
        return redirect(url_for('inventario'))

    if request.method == 'POST':
        print('post')
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user_data = cursor.fetchone()
        print(user_data)
        if user_data is None:
            flash('El usuario no existe.', 'error')
            return redirect(url_for('login'))
        user = User(*user_data)
        if not check_password_hash(user.password, password):
            flash('La contraseña es incorrecta.', 'error')
            return redirect(url_for('login'))
        login_user(user)
        return redirect(url_for('home'))

    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect(url_for('home'))


@app.route('/admin')
@login_required
def admin():
    if current_user.role != 'admin':
        abort(403)
    return render_template('login.html')

@app.route('/inventario')
@login_required
def inventario():
    if current_user.role not in ['admin', 'user']:
        abort(403)
    return render_template('inventario.html')

########################## MAIN FLASK ##############################

if __name__ == '__main__':
    app.run(host='0.0.0.0',port=80,debug=False)



