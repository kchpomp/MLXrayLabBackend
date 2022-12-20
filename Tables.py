from flask_login import UserMixin
from app import db

# Class for Roles table
class Roles(db.Model):
    # __tablename__ = 'roles'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), not_null=True)
    users = db.relationship('Users', backref='roles', lazy='dynamic')

    def __init__(self, name):
        self.name = name

    # def __repr__(self):
    #     return '<Role name %r>' % self.name


# Class for Users table
class Users(UserMixin, db.Model):
    # __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), not_null=True, unique=True)
    e_mail = db.Column(db.String(100), not_null=True)
    password = db.Column(db.String(200), not_null=True)
    role_id = db.Column(db.Integer, db.ForeignKey('roles.id'))
    snapshots = db.relationship('Snapshots', backref='users', lazy='dynamic')

    def __init__(self, username, e_mail, password, role_id):
        self.username = username
        self.e_mail = e_mail
        self.username = username
        self.password = password
        self.role_id = role_id

    # def __repr__(self):
    #     return '<User %r>' % self.username

# Class for Snapshots table

class Snapshots(db.Model):
    __tablename__ = 'snapshots'
    id = db.Column(db.Integer, primary_key=True)
    image_path = db.Column(db.String(500), not_null=True, unique=True)
    mask_path = db.Column(db.String(500), not_null=True, unique=True)
    conclusion = db.Column(db.String(500), not_null=True, unique=True)
    created_at = db.Column(db.Datetime)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    favorite = db.Column(db.Boolean)


    def __init__(self, image_path, mask_path, conclusion, created_at, username):
        self.image_path = image_path
        self.mask_path = mask_path
        self.conclusion = conclusion
        self.created_at = created_at
        self.username = username

    def __repr__(self):
        return '<User %r>' % self.user_id