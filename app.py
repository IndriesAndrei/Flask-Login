from flask import Flask, render_template, request, session, redirect, url_for, flash
import mysql.connector
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField
from wtforms.validators import InputRequired, Email, Length
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from passlib.hash import sha256_crypt
from functools import wraps

app = Flask(__name__)
app.config['SECRET_KEY'] = 'Thisissecret!'
Bootstrap(app)

cnx = mysql.connector.connect(user='root', password='',
                              host='127.0.0.1',
                              database='flasklogin')
cursor = cnx.cursor()


class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember_me')

class RegisterForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=4, max=15)])
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])


# Check if user is logged in
def is_logged_in(f):
    @wraps(f)
    def wrap(*args, **kwargs):
        if 'logged_in' in session:
            return f(*args, **kwargs)
        else:
            return redirect(url_for('login'))
    return wrap


@app.route("/")
def index():
    return render_template('index.html')



@app.route("/login", methods = ['GET', 'POST'])
def login():
    form = LoginForm()

    # we check if the form was submitted
    if form.validate_on_submit():
        # return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'
        username = request.form['username']
        password_candidate = request.form['password']

        
        # Get user by username
        cursor.execute("SELECT * FROM users WHERE username = %s", [username])


        if request.form['password'] == password_candidate and request.form['username'] == username:
            session['logged_in'] = True
            session['username'] = username
            return render_template('index.html')
        else:
            return render_template('login.html')
            
    return render_template('login.html', form = form)




@app.route("/signup", methods = ['GET', 'POST'])
def signup():
    form = RegisterForm()

    # we check if the form was submitted
    if form.validate_on_submit():
        # return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'
        username = form.username.data
        email = form.email.data
        password = sha256_crypt.encrypt(str(form.password.data))

        cursor.execute("INSERT INTO users(username, email, password) VALUES (%s, %s, %s)", (username, email, password))

        #commit to db
        cnx.commit()

      
        flash('You were successfully signed up')
        return render_template('index.html')

    return render_template('signup.html', form = form)


@app.route("/dashboard")
def dashboard():
    return render_template('dashboard.html')

# Logout
@app.route('/logout')
@is_logged_in
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == '__main__':
   app.run(debug=True)
