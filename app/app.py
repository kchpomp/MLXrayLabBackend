from flask import Flask
from flask_mysql_connector import MySQL

# # Initiating login manager options
# login_manager = LoginManager()
# login_manager.session_protection = "strong"
# login_manager.login_view = "login"
# login_manager.login_message_category = "info"
#
# #Initiating MySQL, migrations and bcrypt
# db = MySQL()
# migrate = Migrate()
# bcrypt = Bcrypt()

def create_app():
    app = Flask(__name__)

    # Change this to your secret key (can be anything, it's for extra protection)
    app.secret_key = 'your secret key'

    # Enter your database connection details below
    app.config['MYSQL_HOST'] = 'localhost'
    app.config['MYSQL_USER'] = 'root'
    app.config['MYSQL_PASSWORD'] = 'root'
    app.config['MYSQL_DATABASE'] = 'xraylab'
    app.config['SECRET_KEY'] = 'secret key'
    app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000
    app.config['UPLOAD_FOLDER'] = 'C:/Users/user/Downloads'


    # Intialize MySQL
    mysql = MySQL(app)

    return app, mysql

