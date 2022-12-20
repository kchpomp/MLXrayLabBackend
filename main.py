from flask import Blueprint, render_template, request, redirect, abort, flash
from .Tables import db, Users, Snapshots
from flask_login import login_required, current_user
from datetime import datetime
from werkzeug.utils import secure_filename
from flask_uploads import UploadSet, IMAGES, configure_uploads
from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired, FileAllowed
from wtforms import SubmitField

main = Blueprint('main', __name__)

photos = UploadSet('photos', IMAGES)
configure_uploads(main, photos)

# class UploadForm(FlaskForm):
#     photo = FileField(
#         validators=[
#             FileAllowed = (photos, 'Only Images are allowed'),
#             FileRequired = ('File field should not be empty')
#         ]
#     )
#     submit = SubmitField('upload')

@main.route('/')
def index():
    return render_template('index.html')

@main.route('/profile')
@login_required
def profile():
    return render_template('profile.html', name = current_user.name)

# Users retrieve all operation
@main.route('/users')
@login_required
def RetrieveDataList():
    users = Users.query.all()
    return render_template('userlist.html',users = users)

# Users retrieve one user operation
@main.route('/users/<int:id>')
@login_required
def RetrieveSingleEmployee(id):
    user = Users.query.filter_by(id=id).first()
    if user:
        return render_template('user.html', users = user)
    return f"Employee with id ={id} Does not exist"


# Users update operation
@main.route('/users/<int:id>/update', methods=['GET', 'POST'])
@login_required
def update(id):
    user = Users.query.filter_by(employee_id=id).first()
    if request.method == 'POST':
        if user:
            db.session.delete(user)
            db.session.commit()

            email = request.form.get('email')
            name = request.form.get('name')
            surname = request.form.get('surname')
            username = request.form.get('username')

            user = Users(id=id, email=email, name=name, surname=surname, username=username)

            db.session.add(user)
            db.session.commit()
            return redirect(f'/users/{id}')
        return f"User with id = {id} Does nit exist"

    return render_template('update_user.html', user=user)

# Users delete operation
@main.route('/users/<int:id>/delete', methods=['GET', 'POST'])
@login_required
def delete(id):
    user = Users.query.filter_by(id=id).first()
    if request.method == 'POST':
        if user:
            db.session.delete(user)
            db.session.commit()
            return redirect('/users')
        abort(404)

    return render_template('delete_user.html')


# Snapshots create operation
@main.route('/snapshots/create', methods=['GET', 'POST'])
@login_required
def create():
    if request.method == 'GET':
        return render_template('createsnapshot.html')

    if request.method == 'POST':
        image_path = request.form['image_path']
        mask_path = request.form['mask_path']
        conclusion = request.form['conclusion']
        created_at = datetime.date(datetime.now())
        user = current_user.name
        new_snapshot = Snapshots(image_path=image_path, mask_path=mask_path, conclusion=conclusion, created_at=created_at, user=user)
        db.session.add(new_snapshot)
        db.session.commit()
        return redirect('/snapshots')

# Snapshots retrieve all operation
@main.route('/snapshots')
@login_required
def RetrieveDataList():
    snapshots = Snapshots.query.all()
    return render_template('snapshotlist.html',snapshots = snapshots)

# Snapshots retrieve one operation
@main.route('/snapshots/<int:id>')
@login_required
def RetrieveSingleEmployee(id):
    snapshots = Snapshots.query.filter_by(id=id).first()
    if snapshots:
        return render_template('snapshot.html', snapshots = snapshots)
    return f"Employee with id ={id} Does not exist"

# Snapshots update operation
@main.route('/snapshots/<int:id>/update', methods=['GET', 'POST'])
@login_required
def update(id):
    snapshots = Snapshots.query.filter_by(id=id).first()
    if request.method == 'POST':
        if snapshots:
            db.session.delete(snapshots)
            db.session.commit()

            image_path = request.form.get('email')
            mask_path = request.form.get('name')
            conclusion = request.form.get('surname')
            created_at = datetime.date(datetime.now())
            user = current_user.name

            snapshot = Snapshots(image_path=image_path, mask_path=mask_path, conclusion=conclusion, created_at=created_at, user=user)

            db.session.add(snapshot)
            db.session.commit()
            return redirect(f'/snapshots/{id}')
        return f"Snapshot with id = {id} Does nit exist"

    return render_template('update_snapshot.html', snapshots=snapshots)

# Snapshots delete operation
@main.route('/snapshots/<int:id>/delete', methods=['GET', 'POST'])
@login_required
def delete(id):
    snapshots = Snapshots.query.filter_by(id=id).first()
    if request.method == 'POST':
        if snapshots:
            db.session.delete(snapshots)
            db.session.commit()
            return redirect('/snapshots')
        abort(404)

    return render_template('delete_snapshot.html')

# # Snapshots load image
# @main.route('/snapshots/<int:id>/load', methods=['GET', 'POST'])
# @login_required
# def upload_image(id):
#     if request.method == 'POST':
#         if 'file' not in request.files:
#             flash('No file part')
#             return redirect(request.url)
#
#         file = request.files['file']
#         if file.filename == '':
#             flash('No selected file')
#             return redirect(request.url)
#
#         if file and allowed_file(file.filename):
#             filename = secure_filename(file.filename)
#             file.save(os.path.join(app.config['UPLOAD_FOLDER'], filename))



