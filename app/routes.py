import datetime
import os
from flask import request, redirect, url_for, session, jsonify, flash
from datetime import timezone
import re
from flask_login import (
    LoginManager,
    logout_user,
)
from functools import wraps
import jwt
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
from FileServer import cos, get_obj_url
from app import create_app
import traceback

############################################################################
###   Section dedicated to file extensions and checking file extension   ###
############################################################################
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg'}


###############################################################################
###   Function that allows to check if file has got appropriate extension   ###
###############################################################################
def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


###########################################
###   Decorator for verifying the JWT   ###
###########################################
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        # jwt is passed in the request header
        if 'Authorization' in request.headers:
            token = request.headers['Authorization'].split(" ")[1:][0]
            print("Token for decoding: ", token)
        # return 401 if token is not passed
        if not token:
            return jsonify({'message': 'Token is missing !!'}), 401

        cursor = mysql.connection.cursor()

        try:
            # decoding the payload to fetch the stored details
            try:
                data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            except jwt.ExpiredSignatureError:
                return jsonify({"message": "Token has expired"})
            print("Data: ", data)
            print("Data ID: ", data['id'])
            query = '''SELECT * FROM Users WHERE id = %s'''
            cursor.execute(query, (data['id'],))
            user_info = cursor.fetchone()
            print("User info: ", user_info)
            if user_info:
                current_user_id = user_info[0]
                print("Current User ID: ", current_user_id)
                # returns the current logged in users contex to the routes
                return f(current_user_id, *args, **kwargs)
            else:
                return jsonify({
                    'message': 'Token is invalid !!'
                }), 401
        except Exception as e:
            return jsonify({
                'message': 'Error: ' + str(e)
            })
        finally:
            cursor.close()

    return decorated


#################################
###   Create the app itself   ###
#################################
app, mysql = create_app()
bucket_name = 'xraylabbucket'
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


############################################################################################
### First page. If User logged in then loaded homepage, else redirection to login page   ###
############################################################################################
# @app.route("/", methods=("GET", "POST"), strict_slashes=False)
# def index():
#     if 'loggedin' in session:
#         return redirect(url_for('home'))
#     else:
#         return redirect(url_for('login'))


########################################
###   Function that performs Login   ###
########################################
@app.route("/login", methods=("GET", "POST"), strict_slashes=False)
def login():
    cursor = mysql.connection.cursor()
    if request.method == 'GET':
        return jsonify({"response": "Successfull GET request to Login page"})
    if request.method == 'POST':
        # and 'username' in request.form and 'password' in request.form:
        try:
            # username = request.form['username']
            # password = request.form['password']
            # content = request.get_json(silent=True)
            content = request.get_json()
            print(content)
            print(content['username'])
            print(content['password'])

            query = '''SELECT * FROM Users WHERE username = %s'''
            # cursor.execute(query, (username, password))
            cursor.execute(query, (content['username'], ))

            account = cursor.fetchone()
            print("Password ", account[2])
            hashed_password = generate_password_hash(content['password'], method='sha256')
            print("Hashed password", hashed_password)
            if account:
                if check_password_hash(account[2], content['password']):
                    session['loggedin'] = True
                    session['id'] = account[0]
                    session['username'] = account[1]

                    # Added JWT token that is built if User is successfully authenticated
                    payload_data = {
                        "id": account[0],
                        "username": account[1],
                        "email": account[3],
                        "exp": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(hours=2)
                    }
                    token = jwt.encode(
                        payload=payload_data,
                        key=app.config['SECRET_KEY'],
                        algorithm = "HS256"
                    )
                    print(token)
                    # return redirect(url_for('/home'))
                    return jsonify({"response": "Logged in Successfully",
                                    "token": token})
                else:
                    return jsonify({"response": "Incorrect password! Please, try again."})
            else:
                flash('Incorrect username! Try again.')
                return jsonify({"response": "Incorrect username! Please, try again."})
        except Exception as e:
            flash('Error: ' + str(e))
            print('Error: ' + str(e))
            return jsonify({"response": "Error: " + str(e)})
        finally:
            cursor.close()
            print('Connection to MySQL is closed')



###############################################
###   Funtions that performs registration   ###
###############################################
@app.route("/register", methods=("GET", "POST"), strict_slashes=False)
def register():
    if request.method == 'GET':
        return jsonify({"response": "Registration page successfully reached"})

    if request.method == 'POST':
        cursor = mysql.connection.cursor()

        try:
            role_id = 3
            content = request.get_json(silent=True)
            exist_query = '''SELECT * FROM Users WHERE username = %s'''
            # cursor.execute(exist_query, (username,))
            cursor.execute(exist_query, (content['username'],))
            account = cursor.fetchone()
            print("Account: ", account)
            if account:
                flash('Account already exists!')
                return jsonify({"response": "Account already exists!"})
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', content['email']):
                flash('Invalid email address!')
                return jsonify({"response": "Invalid email address!"})
            elif not re.match(r'[A-Za-z0-9]+', content['username']):
                flash('Username must contain only characters and numbers!')
                return jsonify({"response": "Username must contain only characters and numbers!"})
            elif not content['username'] or not content['password'] or not content['email']:
                flash('Please, fill out the form!')
                return jsonify({"response": "Please fill out the form!"})
            else:
                query = '''INSERT INTO Users(username, password, e_mail, role_id) VALUES (%s, %s, %s, %s)'''

                hashed_password = generate_password_hash(content['password'])
                cursor.execute(query, (content['username'],
                                       hashed_password,
                                       content['email'], role_id,))
                mysql.connection.commit()


                # Create folders for images and masks of the user automatically in Cloud Storage
                cos.put_object(Bucket=bucket_name, Key=(str(content['username']) + '/images'))
                cos.put_object(Bucket=bucket_name, Key=(str(content['username']) + '/masks'))

                jwtQuery = '''SELECT * FROM Users WHERE username=%s'''
                cursor.execute(jwtQuery, (content['username'],))
                account = cursor.fetchone()
                # Added JWT token that is built if User is successfully authenticated
                payload_data = {
                    "id": account[0],
                    "username": account[1],
                    "email": account[3],
                    "exp": datetime.datetime.now(tz=timezone.utc) + datetime.timedelta(hours=2)
                }
                token = jwt.encode(
                    payload=payload_data,
                    key=app.config['SECRET_KEY'],
                    algorithm="HS256"
                )

                return jsonify({"response": "User successfully registered!",
                                "token": token})
        except Exception as e:
            print('Error: ' + str(e))
            tb = traceback.format_exc()
            print(tb)
            return jsonify({"response": "Error: " + str(e)})
        finally:
            cursor.close()

##################################################################
###   Function that allows to process homepage: contains GET   ###
##################################################################
@app.route("/home/", methods=["GET", "POST"], strict_slashes=False)
# @login_required
@token_required
def user_info(current_user_id):
    print(current_user_id)
    if request.method == 'GET':
        query = '''SELECT * FROM Users WHERE id = %s'''
        cursor = mysql.connection.cursor()
        try:
            cursor.execute(query, (int(current_user_id),))
            account = cursor.fetchone()
            print("Account: ", account)
            if account:
                user_info = {
                    'id': account[0],
                    'username': account[1],
                    'email': account[3]
                }
                flash('Welcome back, ' + account[1])

                return jsonify({"user_id": account[0],
                                "username": account[1],
                                "email": account[3]})
            else:
                return jsonify({"response": "User with such id not found"})

        except Exception as e:
            flash('Error: ' + str(e))
            print('Error: ' + str(e))
            tb = traceback.format_exc()
            print(tb)
            return jsonify({'Error: ' + str(e)})
        finally:
            cursor.close()
            print('Connection to MySQL closed')

##########################################################
###    Function that allows to update User's profile   ###
##########################################################
@app.route("/home/update", methods=["GET", "POST"], strict_slashes=False)
@token_required
def update_user(current_user_id):
    if request.method == 'GET':
        return jsonify({"response: ", "User updating page is reached"})

    elif request.method == 'POST':
        print("Accessed")
        cursor = mysql.connection.cursor()
        content = request.get_json(silent=True)
        print("Content: ", content["username"])
        print(type(content))
        if all(i in content for i in ("username", "email", "password")):
            values = (
                content["username"],
                content["email"],
                content["password"],
                current_user_id
            )
            UpdateQuery = '''UPDATE Users SET username=%s, e_mail=%s, password=%s WHERE id=%s'''

            # Checking if username and email are appropriate
            query = '''SELECT * FROM Users WHERE username=%s'''
            cursor.execute(query, (content['username'],))
            account = cursor.fetchone()
            if account:
                return jsonify({'response': 'This username already exists!'})
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', content['email']):
                return jsonify({'response':'Invalid email address !'})
            elif not re.match(r'[A-Za-z0-9]+', content['username']):
                return jsonify({'response':'name must contain only characters and numbers !'})

            query = '''SELECT * FROM Users WHERE e_mail=%s'''
            cursor.execute(query, (content['email'],))
            account = cursor.fetchone()
            if account:
                return jsonify({'response': 'This email already exists!'})
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', content['email']):
                return jsonify({'response':'Invalid email address !'})
            elif not re.match(r'[A-Za-z0-9]+', content['username']):
                return jsonify({'response':'name must contain only characters and numbers !'})

        elif all(i in content for i in ("username", "email")):
            values = (
                    content['username'],
                    content['email'],
                    current_user_id
            )
            UpdateQuery = '''UPDATE Users SET username=%s, e_mail=%s WHERE id=%s'''
            query = '''SELECT * FROM Users WHERE username=%s'''
            cursor.execute(query, (content['username'],))
            account = cursor.fetchone()
            if account:
                return jsonify({'response': 'This username already exists!'})
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', content['email']):
                return jsonify({'response':'Invalid email address !'})
            elif not re.match(r'[A-Za-z0-9]+', content['username']):
                return jsonify({'response':'Username must contain only characters and numbers !'})

            query = '''SELECT * FROM Users WHERE e_mail=%s'''
            cursor.execute(query, (content['email'],))
            account = cursor.fetchone()
            if account:
                return jsonify({'response': 'This email already exists!'})
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', content['email']):
                return jsonify({'response':'Invalid email address !'})
            elif not re.match(r'[A-Za-z0-9]+', content['username']):
                return jsonify({'response':'Username must contain only characters and numbers !'})

        elif all(i in content for i in ("username", "password")):
            values = (
                content['username'],
                content['password'],
                current_user_id
            )
            UpdateQuery = '''UPDATE Users SET username=%s, password=%s WHERE id=%s'''

            query = '''SELECT * FROM Users WHERE username=%s'''
            cursor.execute(query, (content['username'],))
            account = cursor.fetchone()
            if account:
                return jsonify({'response': 'This username already exists!'})
            elif not re.match(r'[A-Za-z0-9]+', content['username']):
                return jsonify({'response':'Username must contain only characters and numbers !'})

        elif all(i in content for i in ("email", "password")):
            values = (
                content["email"],
                content["password"],
                current_user_id
            )
            UpdateQuery = '''UPDATE Users SET e_mail=%s, password=%s WHERE id=%s'''

            query = '''SELECT * FROM Users WHERE e_mail=%s'''
            cursor.execute(query, (content['email'],))
            account = cursor.fetchone()
            if account:
                return jsonify({'response': 'This email already exists!'})
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', content['email']):
                return jsonify({'response': 'Invalid email address !'})

        elif "username" in content:
            values = (
                content["username"],
                current_user_id
            )
            UpdateQuery = '''UPDATE Users SET username=%s WHERE id=%s'''
            query = '''SELECT * FROM Users WHERE username=%s'''
            cursor.execute(query, (content['username'],))
            account = cursor.fetchone()
            if account:
                return jsonify({'response': 'This username already exists!'})
            elif not re.match(r'[A-Za-z0-9]+', content['username']):
                return jsonify({'response': 'Username must contain only characters and numbers !'})
        elif "email" in content:
            values = (
                content["email"],
                current_user_id
            )
            UpdateQuery = '''UPDATE Users SET e_mail=%s WHERE id=%s'''
            query = '''SELECT * FROM Users WHERE e_mail=%s'''
            cursor.execute(query, (content['email'],))
            account = cursor.fetchone()
            if account:
                return jsonify({'response': 'This email already exists!'})
            elif not re.match(r'[^@]+@[^@]+\.[^@]+', content['email']):
                return jsonify({'response': 'Invalid email address !'})
        elif "password" in content:
            values = (
                content["password"],
                current_user_id
            )
            UpdateQuery = '''UPDATE Users SET password=%s WHERE id=%s'''
        else:
            return jsonify({"response": "Please, fill out the form!"})

        try:
            if values:
                cursor.execute(UpdateQuery,  values)
                mysql.connection.commit()
                print("You have successfully updated your personal information")
                return jsonify({"response": "You have successfully updated your personal information"})
            else:
                print("Values for update are missing")
                return jsonify({"response": "Values for update are missing!"})
        except Exception as e:
            print('Error: ' + str(e))
            return jsonify({"response": "Error: " + str(e)})
        finally:
            cursor.close()


######################################################
###   Function that returns all User's snapshots   ###
######################################################
@app.route("/home/user_snapshots", methods=['GET', 'POST'], strict_slashes=False)
@token_required
def list_snapshots(current_user_id):
    if request.method == 'GET':
        cursor = mysql.connection.cursor()
        try:
            query = '''SELECT * FROM Snapshots WHERE user_id=%s'''
            cursor.execute(query, (current_user_id,))
            flash("All User's snapshots successfully loaded")
            data = cursor.fetchall()
            print("Snapshots data: ", data)
            print(data[0])
            print(type(data))
            data_list = []
            for row in data:
                data_dict = {
                    "id": row[0],
                    "note": row[1],
                    "status": row[2],
                    "image_path": row[3],
                    "mask_path": row[4],
                    "conclusion": row[5],
                    "created_at": row[6],
                    "user_id": row[7],
                    "favorite": row[8]
                }
                data_list.append(data_dict)
            return jsonify(data_list)
        except Exception as e:
            flash('Error: ' + str(e))
            print('Error: ' + str(e))
        finally:
            cursor.close()
    if request.method == 'POST':
        return jsonify({"response": "To load a snapshot redirect to another page"})


########################################################################
###   Function that returns one User snapshot according to it's ID   ###
###   If method == 'GET' then loaded one snapshot according to ID    ###
###   If method == 'POST' then it is allowed to UPDATE snapshot      ###
########################################################################
@app.route("/home/user_snapshots/<int:id>", methods=['GET', 'POST'], strict_slashes=False)
@token_required
def list_snapshot_id(current_user_id, id):
    cursor = mysql.connection.cursor()
    # Part that allows to load information about snapshot
    if request.method == 'GET':
        try:
            query = '''SELECT * FROM Snapshots WHERE user_id=%s and id=%s'''
            cursor.execute(query, (current_user_id, id))
            data = cursor.fetchone()
            data_dict = {
                "id": data[0],
                "note": data[1],
                "status": data[2],
                "image_path": data[3],
                "mask_path": data[4],
                "conclusion": data[5],
                "created_at": data[6],
                "user_id": data[7],
                "favorite": data[8]
            }
            return jsonify(data_dict)
        except Exception as e:
            return jsonify({"response": "Error: " + str(e)})
        finally:
            cursor.close()

    # Part that allows to UPDATE information in snapshot
    elif request.method == 'POST':
        try:
            content = request.get_json(silent=True)
            query = '''SELECT * from Snapshots WHERE user_id=%s and id=%s'''
            cursor.execute(query, (current_user_id, id,))
            data = cursor.fetchone()

            if content:
                try:
                    if "image_path" in content:
                        if content["image_path"] != data[3] and content["image_path"]:
                            UpdateQuery = '''UPDATE Snapshots SET image_path=%s WHERE user_id=%s and id=%s'''
                            cursor.execute(UpdateQuery, (content["image_path"], current_user_id, id,))
                            cursor.commit()
                    if "mask_path" in content:
                        if content["mask_path"] != data[4] and content["mask_path"]:
                            UpdateQuery = '''UPDATE Snapshots SET mask_path=%s WHERE user_id=%s and id=%s'''
                            cursor.execute(UpdateQuery, (content["mask_path"], current_user_id, id,))
                            cursor.commit()
                    if "conclusion" in content:
                        if content["conclusion"] != data[5] and content["conclusion"]:
                            UpdateQuery = '''UPDATE Snapshots SET conclusion=%s WHERE user_id=%s and id=%s'''
                            cursor.execute(UpdateQuery, (content["conclusion"], current_user_id, id,))
                            cursor.commit()
                    if "favorite" in content:
                        if content["favorite"] != data[8] and content["favorite"]:
                            UpdateQuery = '''UPDATE Snapshots SET favorite=%s WHERE user_id=%s and id=%s'''
                            cursor.execute(UpdateQuery, (content["favorite"], current_user_id, id,))
                            cursor.commit()
                    if "note" in content:
                        if content["note"] != data[1] and content["note"]:
                            UpdateQuery = '''UPDATE Snapshots SET note=%s WHERE user_id=%s and id=%s'''
                            cursor.execute(UpdateQuery, (content["note"], current_user_id, id,))
                            cursor.commit()
                    if "status" in content:
                        if content["status"] != data[2] and content["status"]:
                            UpdateQuery = '''UPDATE Snapshots SET status=%s WHERE user_id=%s and id=%s'''
                            cursor.execute(UpdateQuery, (content["status"], current_user_id, id,))
                            cursor.commit()

                    UpdateQuery = '''UPDATE Snapshots SET created_at=% WHERE user_id=%s and id=%s'''
                    cursor.execute(UpdateQuery, (datetime.datetime.now(), current_user_id, id))
                    cursor.commit()

                    return jsonify({"response": "Updated successfully!"})
                except Exception as e:
                    print("Error: " + str(e))
                    return jsonify({"response": "Error: " + str(e)})
            else:
                flash('Please fill out the form!')
                return jsonify({"response": "Please, fill out the form!"})

        except Exception as e:
            flash("Error: "+str(e))
            return jsonify({"response": "Error: " + str(e)})
        finally:
            cursor.close()


####################################################################
###   Function that allows to upload file to the Cloud Storage   ###
####################################################################
@app.route('/home/upload_image', methods=['POST', 'GET'], strict_slashes=False)
@token_required
def upload_obj(current_user_id):
    if request.method == 'GET':
        return jsonify({"message": "Upload object destination is reachable"})

    elif request.method == 'POST':
        try:
            print("Request.Files: ", request.files)
            if "" not in request.files:
                flash('No file part')
                # return redirect(request.url)
                return jsonify({"response": "No file part"})

            file = request.files['']

            if file.filename == '':
                flash('No selected file')
                # return redirect(request.url)
                return jsonify({"response": "No selected file"})

            if file and allowed_file(file.filename):
                filename = secure_filename(file.filename)
                file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))
                cursor = mysql.connection.cursor()
                query = '''SELECT * FROM Users WHERE id=%s'''
                cursor.execute(query, (current_user_id,))
                data = cursor.fetchone()
                username = data[1]
                cos.upload_file(os.path.join(app.config['UPLOAD_FOLDER'], filename), bucket_name, username + '/images/' + filename)
                img_url = get_obj_url(bucket_name=bucket_name, id=username + '/images/' + filename)

                created_at = datetime.datetime.now()

                insert_query = '''INSERT INTO Snapshots (user_id, image_path, created_at) VALUES (%s, %s, %s)'''
                cursor.execute(insert_query, (current_user_id, img_url, created_at,))
                cursor.commit()
                return jsonify({"message":"File uploaded successfully!",
                                "image URL in Cloud Storage": img_url})
            else:
                return jsonify({"response": "Wrong type of selected file"})

        except Exception as e:
            tb = traceback.format_exc()
            print('Error: ' + str(e))
            print(tb)
            return jsonify({"response": "Error: "  + str(e)})
        finally:
            cursor.close()


##################################################
###   Function that allows to perform Logout   ###
##################################################
@app.route("/logout", strict_slashes=False)
@token_required
def logout():
    logout_user()
    session.pop('logedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return jsonify({"response": "Successfully Logged Out"}), redirect(url_for('login'))



if __name__ == "__main__":
    app.run(debug=True)