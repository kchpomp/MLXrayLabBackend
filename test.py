# /signin post - DONE
# /signup post - DONE
# /snapshots(all) get - DONE
# /snapshots/:id(1) GET/POST - NOT DONE
# /homepage - DONE


import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_mysql_connector import MySQL
from datetime import timedelta
from flask_http_middleware import MiddlewareManager, BaseHTTPMiddleware
import re
from tkinter import Tk
from tkinter.filedialog import askopenfilename
from flask_login import (
    logout_user,
    login_required,
    login_user,
)
from functools import wraps
import boto3
import jwt
from pathlib import Path
import  json
from werkzeug.utils import secure_filename

allowed_filetypes = (
    ('Dicom files', '*.dicom*'),
    ('PNG files', '*.png*'),
    ('JPG files', '*.jpg*'),
    ('Dicom files', '*.dcm'),
    ('All files', '*.*')
)

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

cos = boto3.client(
    's3',
    aws_access_key_id = 'YCAJEq23MSLvRBTVBkQ9-f4kS',
    aws_secret_access_key = 'YCP51sph009N24z5-1fSyvoITeekQAlJbWTJgS31',
    region_name = 'ru-central1',
    endpoint_url = 'https://storage.yandexcloud.net'
)


bucket_name = 'xraylabbucket'

app = Flask(__name__)


# decorator for verifying the JWT
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'jwt' in request.headers:
            token = request.headers['jwt']
        # return 401 if token is not passed
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        cursor = mysql.connection.cursor()

        try:
            # decoding the payload to fetch the stored details
            data = jwt.decode(token, app.config['SECRET_KEY'])
            query = '''SELECT * FROM Users WHERE id = %s'''
            cursor.execute(query, (data['id']))
            user_info = cursor.fetchone()
            if user_info:
                current_user_id = user_info['id']
                # returns the current logged in users contex to the routes
                return f(current_user_id, *args, **kwargs)
        except:
            return jsonify({
                'message': 'Token is invalid !!'
            }), 401
        finally:
            cursor.close()

    return decorated

class SecureRoutersMiddleware(BaseHTTPMiddleware):
    def __init__(self, secured_routers = []):
        super().__init__()
        self.secured_routers = secured_routers

    def dispatch(self, request, call_next):
        if request.path in self.secured_routers:
            if request.headers.get("token") == "secret":
                return call_next(request)
            else:
                return jsonify({"message":"invalid token"})
        else:
            return call_next(request)

secured_routers = ["/home"]

# Change this to your secret key (can be anything, it's for extra protection)
app.secret_key = 'your secret key'

# Enter your database connection details below
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = 'Dd19995678!'
app.config['MYSQL_DATABASE'] = 'xraylab'
app.config['SECRET_KEY'] = 'secret key'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000

app.wsgi_app = MiddlewareManager(app)
app.wsgi_app.add_middleware(SecureRoutersMiddleware, secured_routers=secured_routers)

# Intialize MySQL
mysql = MySQL(app)



@app.before_request
def session_handler():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=1)


# First page. If User logged in then loaded homepage, else redirection to login page
@app.route("/", methods=("GET", "POST"), strict_slashes=False)
def index():
    if 'loggedin' in session:
        return redirect(url_for('home'))
    else:
        return redirect(url_for('login'))


@app.route("/login/", methods=("GET", "POST"), strict_slashes=False)
def login():
    # form = login_form()

    msg = ''
    cursor = mysql.connection.cursor()

    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        try:
            username = request.form['username']
            password = request.form['password']

            query = '''SELECT * FROM Users WHERE username = %s AND password = %s'''
            cursor.execute(query, (username, password))

            account = cursor.fetchone()

            if account:
                session['loggedin'] = True
                session['id'] = account['id']
                session['username'] = account['username']

                msg = 'Logged in successfully!'
                # Added JWT token that is built if User is successfully authenticated
                payload_data = {
                    "id": account["id"],
                    "username": account["username"],
                    "email": account["e_mail"]
                }
                my_secret = "secret"
                token = jwt.encode(
                    payload=payload_data,
                    key=my_secret
                )
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
                mysql.connection.commit()
                msg = 'You have successfully registered!'
                cos.put_object(Bucket=bucket_name, Key=(username + '/images'))
                cos.put_object(Bucket=bucket_name, Key=(username + '/masks'))
        except Exception as e:
            msg = 'Error: ' + str(e)
        finally:
            cursor.close()
            print('Connection to MySQL is closed')
    elif request.method == 'POST':
        msg = 'Please fill out the form!'

    return render_template('register.html', msg=msg)

@app.route("/home", methods=["GET", "POST"], strict_slashes=False)
@login_required
@token_required
def user_info(current_user_id):
    msg = ''
    if request.method == 'GET':
        query = '''SELECT * FROM Users WHERE id = %s'''
        cursor = mysql.connection.cursor()
        try:
            cursor.execute(query, (current_user_id,))
            account = cursor.fetchone()

            if account:
                output = {
                    'id': account['id'],
                    'username': account['username'],
                    'email': account['e_mail']
                }
            return jsonify({"user_info": output})
        except Exception as e:
            msg = 'Error: ' + str(e)
        finally:
            cursor.close()
            print(msg)

@app.route("/home/update", methods=["GET", "POST"], strict_slashes=False)
@login_required
@token_required
def update_user(current_user_id):
    msg = ''
    if request.method == 'POST':
        cursor = mysql.connection.cursor()
        if 'username' in request.form and 'email' in request.form and 'password' in request.form:
            try:
                username = request.form['username']
                email = request.form['email']
                password = request.form['password']
                values = {
                    'username': username,
                    'email': email,
                    'password': password,
                    'id': current_user_id
                }
                UpdateQuery = '''UPDATE Users SET username=%s, e_mail=%s, password=%s WHERE id=%s'''

                query = '''SELECT * FROM Users WHERE username=%s'''
                cursor.execute(query, (username,))
                account = cursor.fetchone()
                if account:
                    msg = 'This username already exists!'
                elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                    msg = 'Invalid email address !'
                elif not re.match(r'[A-Za-z0-9]+', username):
                    msg = 'name must contain only characters and numbers !'

                query = '''SELECT * FROM Users WHERE e_mail=%s'''
                cursor.execute(query, (email,))
                account = cursor.fetchone()
                if account:
                    msg = 'This username already exists!'
                elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                    msg = 'Invalid email address !'
                elif not re.match(r'[A-Za-z0-9]+', username):
                    msg = 'name must contain only characters and numbers !'
            except Exception as e:
                msg = 'Error: ' + str(e)
        elif 'username' in request.form and 'email' in request.form:
            try:
                username = request.form['username']
                email = request.form['email']
                values = {
                    'username': username,
                    'email': email,
                    'id': current_user_id
                }
                UpdateQuery = '''UPDATE Users SET username=%s, e_mail=%s WHERE id=%s'''

                query = '''SELECT * FROM Users WHERE username=%s'''
                cursor.execute(query, (username,))
                account = cursor.fetchone()
                if account:
                    msg = 'This account already exists!'
                elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                    msg = 'Invalid email address !'
                elif not re.match(r'[A-Za-z0-9]+', username):
                    msg = 'name must contain only characters and numbers !'

                query = '''SELECT * FROM Users WHERE e_mail=%s'''
                cursor.execute(query, (email,))
                account = cursor.fetchone()
                if account:
                    msg = 'This username already exists!'
                elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                    msg = 'Invalid email address !'
                elif not re.match(r'[A-Za-z0-9]+', username):
                    msg = 'name must contain only characters and numbers !'
            except Exception as e:
                msg = 'Error: ' + str(e)
        elif 'username' in request.form and 'password' in request.form:
            try:
                username = request.form['username']
                password = request.form['password']
                values = {
                    'username': username,
                    'password': password,
                    'id': current_user_id
                }
                UpdateQuery = '''UPDATE Users SET username=%s, password=%s WHERE id=%s'''

                query = '''SELECT * FROM Users WHERE username=%s'''
                cursor.execute(query, (username,))
                account = cursor.fetchone()
                if account:
                    msg = 'This account already exists!'
                elif not re.match(r'[A-Za-z0-9]+', username):
                    msg = 'name must contain only characters and numbers !'

            except Exception as e:
                msg = 'Error: ' + str(e)
        elif 'email' in request.form and 'password' in request.form:
            try:
                email = request.form['email']
                password = request.form['password']
                values = {
                    'email': email,
                    'password': password,
                    'id': current_user_id
                }
                UpdateQuery = '''UPDATE Users SET e_mail=%s, password=%s WHERE id=%s'''

                query = '''SELECT * FROM Users WHERE e_mail=%s'''
                cursor.execute(query, (email,))
                account = cursor.fetchone()
                if account:
                    msg = 'This username already exists!'
                elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                    msg = 'Invalid email address !'
            except Exception as e:
                msg = 'Error: ' + str(e)
        elif 'username' in request.form:
            try:
                username = request.form['username']
                values = {
                    'username': username,
                    'id': current_user_id
                }
                UpdateQuery = '''UPDATE Users SET username=%s WHERE id=%s'''

                query = '''SELECT * FROM Users WHERE username=%s'''
                cursor.execute(query, (username,))
                account = cursor.fetchone()
                if account:
                    msg = 'This account already exists!'
                elif not re.match(r'[A-Za-z0-9]+', username):
                    msg = 'name must contain only characters and numbers !'
            except Exception as e:
                msg = 'Error: ' + str(e)
        elif 'email' in request.form:
            try:
                email = request.form['email']
                values = {
                    'email': email,
                    'id': current_user_id
                }
                UpdateQuery = '''UPDATE Users SET e_mail=%s WHERE id=%s'''

                query = '''SELECT * FROM Users WHERE e_mail=%s'''
                cursor.execute(query, (email,))
                account = cursor.fetchone()
                if account:
                    msg = 'This username already exists!'
                elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                    msg = 'Invalid email address !'
            except Exception as e:
                msg = 'Error: ' + str(e)
        elif 'password' in request.form:
            try:
                password = request.form['password']
                values = {
                    'password': password,
                    'id': current_user_id
                }
                UpdateQuery = '''UPDATE Users SET password=%s WHERE id=%s'''
            except Exception as e:
                msg = 'Error: ' + str(e)
        else:
            msg = 'Please fill out the form!'
        try:
            if values:
                cursor.execute(UpdateQuery,  [values.values()])
                mysql.connection.commit()
                msg = 'You have successfully updated your personal information'
        except Exception as e:
            msg = "Error: " + str(e)
        finally:
            cursor.close()

        return render_template('user_update.html', msg=msg)
    return redirect(url_for('login'))

# Function that returns all User's snapshots
@app.route("/home/user_snapshots", methods=['GET', 'POST'], strict_slashes=False)
@login_required
@token_required
def list_snapshots(current_user_id):
    msg = ''
    if request.method == 'GET':
        cursor = mysql.connection.cursor()

        query = '''SELECT * FROM Snapshots WHERE user_id=%s'''
        cursor.execute(query, (current_user_id,))

        return jsonify(titles=[row['title'] for row in cursor.fetchall()])

    # elif request.method == 'POST':
    #     image_path = request.form['image_path']
    #     mask_path = request.form['image_path']
    #     conclusion = request.form['conclusion']
    #     created_at = datetime.datetime.now()
    #     user_id = current_user_id
    #     favorite = request.form['favorite']

# Function that returns one User snapshot according to it's ID
@app.route("/home/user_snapshots/<int:id>", methods=['GET', 'POST'], strict_slashes=False)
@login_required
@token_required
def list_snapshot_id(current_user_id, id):
    msg = ''
    cursor = mysql.connection.cursor()
    if request.method == 'GET':

        query = '''SELECT * FROM Snapshots WHERE user_id=%s and id=%s'''
        cursor.execute(query, (current_user_id, id))

        return jsonify(titles=[row['title']] for row in cursor.fetchone())

    # Part that allows to UPDATE information in snapshot
    elif request.method == 'POST':
        try:
            # All four presented
            if 'image_path' in request.form and 'mask_path' in request.form and 'conclusion' in request.form and 'favorite' in request.form:
                image_path = request.form['image_path']
                mask_path = request.form['mask_path']
                conclusion = request.form['conclusion']
                favorite = request.form['favorite']

                UpdateQuery = '''UPDATE Snapshots SET image_path=%s, mask_path=%s, conclusion=%s, favorite=%s WHERE user_id=%s and id=%s'''

                values = {
                    'image_path': image_path,
                    'mask_path': mask_path,
                    'conclusion': conclusion,
                    'favorite': favorite,
                    'user_id': current_user_id,
                    'id': id
                }

            # Three presented
            elif 'image_path' in request.form and 'mask_path' in request.form and 'conclusion' in request.form:
                image_path = request.form['image_path']
                mask_path = request.form['mask_path']
                conclusion = request.form['conclusion']

                UpdateQuery = '''UPDATE Snapshots SET image_path=%s, mask_path=%s, conclusion=%s WHERE user_id=%s and id=%s'''

                values = {
                    'image_path': image_path,
                    'mask_path': mask_path,
                    'conclusion': conclusion,
                    'user_id': current_user_id,
                    'id': id
                }

            elif 'image_path' in request.form and 'mask_path' in request.form and 'favorite' in request.form:
                image_path = request.form['image_path']
                mask_path = request.form['mask_path']
                favorite = request.form['favorite']

                UpdateQuery = '''UPDATE Snapshots SET image_path=%s, mask_path=%s, favorite=%s WHERE user_id=%s and id=%s'''

                values = {
                    'image_path': image_path,
                    'mask_path': mask_path,
                    'favorite': favorite,
                    'user_id': current_user_id,
                    'id': id
                }
            elif 'image_path' in request.form and 'conclusion' in request.form and 'favorite' in request.form:
                image_path = request.form['image_path']
                conclusion = request.form['conclusion']
                favorite = request.form['favorite']

                UpdateQuery = '''UPDATE Snapshots SET image_path=%s, conclusion=%s, favorite=%s WHERE user_id=%s and id=%s'''

                values = {
                    'image_path': image_path,
                    'conclusion': conclusion,
                    'favorite': favorite,
                    'user_id': current_user_id,
                    'id': id
                }
            elif 'mask_path' in request.form and 'conclusion' in request.form and 'favorite' in request.form:
                mask_path = request.form['mask_path']
                conclusion = request.form['conclusion']
                favorite = request.form['favorite']

                UpdateQuery = '''UPDATE Snapshots SET mask_path=%s, conclusion=%s, favorite=%s WHERE user_id=%s and id=%s'''

                values = {
                    'mask_path': mask_path,
                    'conclusion': conclusion,
                    'favorite': favorite,
                    'user_id': current_user_id,
                    'id': id
                }

            # Two presented
            elif 'image_path' in request.form and 'mask_path':
                image_path = request.form['image_path']
                mask_path = request.form['mask_path']

                UpdateQuery = '''UPDATE Snapshots SET image_path=%s, mask_path=%s WHERE user_id=%s and id=%s'''

                values = {
                    'image_path': image_path,
                    'mask_path': mask_path,
                    'user_id': current_user_id,
                    'id': id
                }
            elif 'image_path' and 'conclusion' in request.form:
                image_path = request.form['image_path']
                conclusion = request.form['conclusion']

                UpdateQuery = '''UPDATE Snapshots SET image_path=%s, conclusion=%s WHERE user_id=%s and id=%s'''

                values = {
                    'image_path': image_path,
                    'conclusion': conclusion,
                    'user_id': current_user_id,
                    'id': id
                }
            elif 'image_path' in request.form and 'favorite' in request.form:
                image_path = request.form['image_path']
                favorite = request.form['favorite']

                UpdateQuery = '''UPDATE Snapshots SET image_path=%s, favorite=%s WHERE user_id=%s and id=%s'''

                values = {
                    'image_path': image_path,
                    'favorite': favorite,
                    'user_id': current_user_id,
                    'id': id
                }
            elif 'mask_path' in request.form and 'conclusion' in request.form:
                mask_path = request.form['mask_path']
                conclusion = request.form['conclusion']

                UpdateQuery = '''UPDATE Snapshots SET mask_path=%s, conclusion=%s WHERE user_id=%s and id=%s'''

                values = {
                    'mask_path': mask_path,
                    'conclusion': conclusion,
                    'user_id': current_user_id,
                    'id': id
                }
            elif 'mask_path' in request.form and 'favorite' in request.form:
                mask_path = request.form['mask_path']
                favorite = request.form['favorite']

                UpdateQuery = '''UPDATE Snapshots SET mask_path=%s, favorite=%s WHERE user_id=%s and id=%s'''

                values = {
                    'mask_path': mask_path,
                    'favorite': favorite,
                    'user_id': current_user_id,
                    'id': id
                }
            elif 'conclusion' in request.form and 'favorite' in request.form:
                conclusion = request.form['conclusion']
                favorite = request.form['favorite']

                UpdateQuery = '''UPDATE Snapshots SET conclusion=%s, favorite=%s WHERE user_id=%s and id=%s'''

                values = {
                    'conclusion': conclusion,
                    'favorite': favorite,
                    'user_id': current_user_id,
                    'id': id
                }

            # One presented
            elif 'image_path' in request.form:
                image_path = request.form['image_path']

                UpdateQuery = '''UPDATE Snapshots SET image_path=%s WHERE user_id=%s and id=%s'''

                values = {
                    'image_path': image_path,
                    'user_id': current_user_id,
                    'id': id
                }
            elif 'mask_path' in request.form:
                mask_path = request.form['mask_path']

                UpdateQuery = '''UPDATE Snapshots SET mask_path=%s WHERE user_id=%s and id=%s'''

                values = {
                    'mask_path': mask_path,
                    'user_id': current_user_id,
                    'id': id
                }
            elif 'conclusion' in request.form:
                conclusion = request.form['conclusion']

                UpdateQuery = '''UPDATE Snapshots SET conclusion=%s WHERE user_id=%s and id=%s'''

                values = {
                    'conclusion': conclusion,
                    'user_id': current_user_id,
                    'id': id
                }
            elif 'favorite' in request.form:
                favorite = request.form['favorite']

                UpdateQuery = '''UPDATE Snapshots SET favorite=%s WHERE user_id=%s and id=%s'''

                values = {
                    'favorite': favorite,
                    'user_id': current_user_id,
                    'id': id
                }
            else:
                flash('Please fill out the form!')
            try:
                if values:
                    cursor.execute(UpdateQuery, [values.values()])
                    mysql.connection.commit()
                    flash('Updated Successfully')
            except Exception as e:
                flash("Error: "+str(e))

        except Exception as e:
            flash("Error: "+str(e))

        finally:
            cursor.close()

        return redirect(url_for('/home/user_snapshots'))




@app.route('/upload_image', methods=['POST', 'GET'], strict_slashes=False)
@login_required
@token_required
def upload_obj(current_user_id):
    if request.method == 'POST':
        try:
            if 'file' not in request.files:
                flash('No file part')
                return redirect(request.url)
            file = request.files['file']

            if file.filename == '':
                flash('No selected file')
                return redirect(request.url)

            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                cos.upload_file(filename, bucket_name, current_user_id+'/'+ file.filename)

        except Exception as e:
            msg = 'Error: ' + str(e)

    # try:
    #     Tk().withdraw()
    #     filename = askopenfilename(title='Select file', filetypes=allowed_filetypes)
    #
    #     cos.upload_file(filename, bucket_name, Path(filename).name)
    #
    # except Exception as e:
    #     return json.dumps({'error': str(e)})



@app.route("/logout", strict_slashes=False)
@login_required
# @jwt_required(fresh=True)
def logout():
    logout_user()
    session.pop('logedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))


if __name__ == "__main__":
    app.run(debug=True)