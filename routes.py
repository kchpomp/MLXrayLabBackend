from flask import (
    Flask,
    render_template,
    redirect,
    flash,
    url_for,
    session,
    request
)

from datetime import timedelta
from sqlalchemy.exc import (
    IntegrityError,
    DataError,
    DatabaseError,
    InterfaceError,
    InvalidRequestError,
)
from werkzeug.routing import BuildError

from flask_bcrypt import Bcrypt, generate_password_hash, check_password_hash

from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    current_user,
    logout_user,
    login_required,
)

from app import create_app, login_manager, bcrypt
from flask_mysql_connector import MySQL

# from forms import login_form, register_form

from flask_jwt_extended import create_access_token, create_refresh_token
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
import re


# @login_manager.user_loader
# def load_user(user_id):
#     return Users.query.get(int(user_id))


app = create_app()
mysql = MySQL(app)
jwt = JWTManager(app)


@app.before_request
def session_handler():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=1)


# @app.route("/", methods=("GET", "POST"), strict_slashes=False)
# def index():
#     return render_template("index.html", title="Home")


@app.route("/login/", methods=("GET", "POST"), strict_slashes=False)
def login():
    # form = login_form()

    msg = ''
    cursor = mysql.connection.cursor()

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        try:
            username = request.form['username']
            password = request.form['password']

            cursor = app.connection.cursor()
            query = '''SELECT * FROM Users WHERE username = %s AND password = %s'''
            cursor.execute(query, (username, password))

            account = cursor.fetchone()

            if account:
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']

                msg = 'Logged in successfully!'
            else:
                msg = 'Incorrect username/password! Try again.'
        except Exception as e:
            msg = 'Error: ' + str(e)
        finally:
            cursor.close()
            print('Connection to MySQL is closed')

    return render_template('auth.html', msg=msg)

# Register route
@app.route("/register/", methods=("GET", "POST"), strict_slashes=False)
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form:
        cursor = mysql.connection.cursor()

        try:
            username = request.form['username']
            password = request.form['password']
            email = request.form['email']
            role_id = 3

            exist_query = '''SELECT * FROM Users WHERE username = %s'''
            cursor.execute(exist_query, (username,))
            account = cursor.fetchone()

            if account:
                msg = 'Account already exists!'
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                msg = 'Invalid email address!'
            elif not re.match(r'[A-Za-z0-9]+', username):
                msg = 'Username must contain only characters and numbers!'
            elif not username or not password or not email:
                msg = 'Please fill out the form!'
            else:
                query = '''INSERT INTO Users(username, password, e_mail, role_id) VALUES (%s, %s, %s, %s)'''
                cursor.execute(query, (username, password, email, role_id))
                app.connection.commit()
                msg = 'You have successfully registered!'
        except Exception as e:
            msg = 'Error: ' + str(e)
        finally:
            cursor.close()
            print('Connection to MySQL is closed')
    elif request.method == 'POST':
        msg = 'Please fill out the form!'

    return render_template('register.html', msg=msg)

@app.route("/logout")
@login_required
@jwt_required(fresh=True)
def logout():
    logout_user()
    session.pop('logedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)