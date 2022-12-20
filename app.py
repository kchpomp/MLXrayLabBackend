from flask import Flask, session
from flask_mysql_connector import MySQL
from flask_login import (
    UserMixin,
    login_user,
    LoginManager,
    current_user,
    logout_user,
    login_required,
)
from datetime import timedelta
from flask_jwt_extended import create_access_token
from flask_jwt_extended import get_jwt
from flask_jwt_extended import get_jwt_identity
from flask_jwt_extended import jwt_required
from flask_jwt_extended import JWTManager
from flask_jwt_extended import set_access_cookies
from flask_jwt_extended import unset_jwt_cookies
from flask_bcrypt import Bcrypt
from flask_migrate import Migrate

# Initiating login manager options
login_manager = LoginManager()
login_manager.session_protection = "strong"
login_manager.login_view = "login"
login_manager.login_message_category = "info"

#Initiating MySQL, migrations and bcrypt
db = MySQL()
migrate = Migrate()
bcrypt = Bcrypt()

def create_app():
    app = Flask(__name__)

    app.secret_key = 'secret-key'
    app.config['MYSQL_DATABASE_HOST'] = 'localhost'
    app.config['MYSQL_DATABASE_USER'] = 'root'
    app.config['MYSQL_DATABASE_PASSWORD'] = 'Dd19995678!'
    app.config['MYSQL_DATABASE_DB'] = 'xraylab'
    app.config['MYSQL_TRACK_MODIFICATIONS'] = True

    app.config['UPLOADED_PHOTO_DEST'] = 'uploads'
    app.config["JWT_COOKIE_SECURE"] = False
    app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
    app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this in your code!
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
    app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=30)

    login_manager.init_app(app)
    db.init_app(app)
    migrate.init_app(app, db)
    bcrypt.init_app(app)

    return app



# def create_app():
#     app = Flask(__name__)
#
#     app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root:Dd19995678!@localhost/xraylab'
#     app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
#     app.config['UPLOADED_PHOTO_DEST'] = 'uploads'
#     # If true this will only allow the cookies that contain your JWTs to be sent
#     # over https. In production, this should always be set to True
#     app.config["JWT_COOKIE_SECURE"] = False
#     app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
#     app.config["JWT_SECRET_KEY"] = "super-secret"  # Change this in your code!
#     app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)
#
#     jwt = JWTManager(app)
#
#
#     db.init_app(app)
#
#     login_manager = LoginManager()
#     login_manager.login_view = 'auth.login'
#     login_manager.init_app(app)
#
#     from .Tables import Users
#
#     @login_manager.user_loader
#     def load_user(user_id):
#         # since the user_id is just the primary key of our user table, use it in the query for the user
#         return Users.query.get(int(user_id))
#
#     # blueprint for auth routes in our app
#     from .auth import auth as auth_blueprint
#     app.register_blueprint(auth_blueprint)
#
#     # blueprint for non-auth parts of app
#     from .main import main as main_blueprint
#     app.register_blueprint(main_blueprint)
#
#     return app


#
# if __name__ == '__main__':
#     app = create_app()
#     app.run()
