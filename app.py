from flask import Flask, render_template, redirect, url_for, request, flash, session
from flask_mysqldb import MySQL
from datetime import datetime, timedelta
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'mysecretkey'
app.config['MYSQL_HOST'] = 'ventas_flask'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = '39023902'
app.config['MYSQL_DB'] = 'mydatabase'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

mysql = MySQL(app)

@app.route('/')
def home():
    if 'username' in session:
        return render_template('home.html', username=session['username'])
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        cursor = mysql.connection.cursor()
        cursor.execute('SELECT * FROM users WHERE username = %s', (username,))
        user_data = cursor.fetchone()
        if user_data is None:
            flash('El usuario no existe.', 'error')
            return redirect(url_for('login'))
        _, _, hashed_password = user_data
        if not check_password_hash(hashed_password, password):
            flash('La contraseña es incorrecta.', 'error')
            return redirect(url_for('login'))
        session['username'] = username
        session.permanent = True
        return redirect(url_for('home'))
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)
