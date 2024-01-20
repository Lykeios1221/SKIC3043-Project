import io
import json
import os
import re
from datetime import datetime
from functools import wraps
from pathlib import Path
from smtplib import SMTPException

from flask import render_template, request, flash, url_for, redirect, jsonify, send_from_directory, abort
from flask_apscheduler import APScheduler
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter, RateLimitExceeded
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, current_user, login_user, login_required, logout_user
from flask_mail import Mail, Message
from pypdf import PdfReader
from pypdf.errors import PyPdfError
from sqlalchemy import exc
from werkzeug.utils import secure_filename

from app import app
from app_logging import log_access_activity, log_error
from model import User, db, EmailAuthenticator, Profile, Revenue, Expense, Inventory, LoginForm, SignupForm, \
    ResetPasswordForm

bcrypt = Bcrypt(app)
mail = Mail(app)

scheduler = APScheduler(app=app)
scheduler.start()

login_manager = LoginManager(app)
login_manager.login_view = 'index'
login_manager.login_message = u"Login session invalid. Please login again."
login_manager.refresh_view = "index"
login_manager.needs_refresh_message = u'Login session has expired. Please login again.'
login_manager.needs_refresh_message_category = 'danger'
login_manager.login_message_category = 'danger'

tokens = []

limiter = Limiter(app=app, key_func=lambda: current_user.email, storage_uri="memory://", )


@login_manager.user_loader
def user_loader(user_email):
    return User.query.get(user_email)


def limit_content_length(max_length):
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            cl = request.content_length
            if cl is not None and cl > max_length:
                abort(413)
            return f(*args, **kwargs)

        return wrapper

    return decorator


@app.route('/', methods=['GET'])
def index():
    login_form = LoginForm()
    sign_up_form = SignupForm()
    return render_template('index.html', login_form=login_form, sign_up_form=sign_up_form)


@app.route('/login', methods=['POST'])
def login():
    logout_user()
    form = LoginForm()
    # Validate form input
    if form.validate_on_submit():
        email = form.login_email.data
        password = form.login_password.data
        try:
            check_login_attempts_for_ip(email)
            user = User.query.filter_by(email=email).first()
            if user and user.authorized_status == 1:
                password_valid = bcrypt.check_password_hash(user.password, password)
                if not password_valid:
                    check_login_attempts_for_email(email)
                    flash('Invalid credentials for login. Please try again.', 'danger')
                else:
                    login_user(user)
                    log_access_activity(f"User '{user.username}' with email '{email}' has logged in.")
                    flash(f'Welcome back, User {user.username}', 'success')
                    return redirect(url_for('display_assets')) if user.has_role('user') else redirect(
                        url_for('admin_dashboard'))
            else:
                flash('Invalid credentials for login. Please try again.', 'danger')
        except RateLimitExceeded as e:
            log_access_activity(f"Rate limit exceeded for login attempts of email {email}. Error: {e.description}")
            flash('Rate limit exceeded for login attempt. Try again later.', 'danger')
    else:
        flash('Invalid input for login. Please check your credentials and try again.', 'danger')
    return redirect(url_for('index'))


@limiter.limit("3 per minute", key_func=lambda: f"failed_login:{request.form.get('email')}",
               error_message='Failed login attempts.')
def check_login_attempts_for_email(email):
    log_access_activity(f"Failed login attempt for user with email '{email}'.")


@limiter.limit("5 per minute", key_func=get_remote_address, error_message='Too many attempts.')
def check_login_attempts_for_ip(email):
    log_access_activity(f"Login attempt for user with email '{email}'.")


@limiter.limit("3 per minute", key_func=lambda: f"failed_login:{request.form.get('email')}",
               error_message='Failed login attempts.')
@app.route('/signup', methods=['POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.signup_email.data
        password = form.signup_password.data
        try:
            check_signup_attempts_for_ip(email)
            hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
            new_user = User(username=name, email=email, password=hashed_password, authorized_status=0)
            db.session.add(new_user)
            db.session.commit()

            # Generate token for email authentication
            token = EmailAuthenticator.generate_token(email)
            tokens.append(token)
            confirm_url = url_for("confirm_email", token=token, _external=True)
            subject = "SKIC3043: Please confirm your email"
            msg = Message(subject, recipients=[email],
                          html=render_template('verification-email.html', confirm_url=confirm_url),
                          sender='flaskemailbotf@gmail.com', )
            mail.send(message=msg)
            log_access_activity(f"User '{name}' signed up with email '{email}'. Verification email sent.")
            return render_template('verify-request.html')
        except exc.IntegrityError as e:
            db.session.rollback()
            log_error(f"IntegrityError: {str(e)}")
            flash("An unexpected error occurred. Try again later.", 'danger')
        except exc.SQLAlchemyError as e:
            db.session.rollback()
            log_error(f"MySQL Error: {str(e)}")
            flash("An unexpected error occurred. Try again later.", 'danger')
        except SMTPException as e:
            log_error(f"Mailing Error for sign-up: {str(e)}")
            flash("An unexpected error occurred. Try again later.", 'danger')
        except RateLimitExceeded as e:
            log_access_activity(f"Rate limit exceeded for sign-up attempts of email. Error: {e.description}")
            flash('Rate limit exceeded for sign-up attempt. Try again later.', 'danger')
        except Exception as e:
            log_error(f"An unexpected error occurred: {str(e)}")
            flash("An unexpected error occurred. Try again later.", 'danger')
    else:
        flash('Invalid input for sign-up. Try again later.', 'danger')
    return redirect(url_for('index'))


@limiter.limit("3 per minute", key_func=get_remote_address, error_message='Too many attempts.')
def check_signup_attempts_for_ip(email):
    log_access_activity(f"Sign-up attempt with email '{email}'.")


@app.route('/verify_email_duplicate', methods=["GET"])
def verify_email_duplicate():
    email = request.args['email']
    try:
        user = User.query.filter_by(email=email).first()
        if user:
            # Authorized existing email
            if user.authorized_status == 1:
                log_access_activity(
                    f"Email duplication verification for '{email}' was successful. Duplicated status = True.")
                return 'True'
            else:
                # Unauthorized email waiting for verification
                log_access_activity(f"Email '{email}' registered failed due to waiting for verification")
                return 'Verifying'
        else:
            # Email is available
            log_access_activity(
                f"Email duplication verification for '{email}' was successful. Duplicated status = False.")
            return 'False'

    except exc.SQLAlchemyError as e:
        log_error(f"MySQL Error during email verification: {str(e)}")
        return "Error"
    except Exception as e:
        log_error(f"An unexpected error occurred during email verification: {str(e)}")
        return "Error"


@app.route("/confirm/<token>")
def confirm_email(token):
    try:
        valid, email = EmailAuthenticator.confirm_token(token)
        user = User.query.filter_by(email=email).first()
        if user:
            if valid:
                user.authorized_status = 1
                profile = Profile(email=email)
                db.session.add(user)
                db.session.commit()
                # Create profile for the authorized user
                db.session.add(profile)
                db.session.commit()
                log_access_activity(f"User with email '{email}' is verified.")
                flash("You have confirmed your account. Thanks!", "success")
                login_user(user)
                return redirect(url_for('profile'))
            else:
                db.session.delete_asset(user)
                db.session.commit()
                flash("The confirmation link has expired.", "danger")
        else:
            flash("The confirmation link is invalid.", "danger")
    except exc.SQLAlchemyError as e:
        db.session.rollback()
        log_error(f"Error during database transaction for confirm email.: {str(e)}")
        flash("An error occurred while processing your request. Please try again later.", "danger")
    except Exception as e:
        log_error(f"An error occurred during email confirmation: {str(e)}")
        flash("An unexpected error occurred. Please try again later.", "danger")
    return redirect(url_for('index'))


@app.route('/forgot_password_page')
def forgot_password_page():
    form = ResetPasswordForm()
    return render_template('forgot-password.html', form=form)


@app.route('/send_reset_email', methods=['POST'])
def send_reset_email():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        email = request.form['email']
        try:
            check_reset_password_rate(email)
            if User.query.get(email):
                token = EmailAuthenticator.generate_token(email)
                tokens.append(token)
                confirm_url = url_for("confirm_reset_password", token=token, _external=True)
                subject = "SKIC3043: Request for reset password"
                msg = Message(subject, recipients=[email],
                              html=render_template('reset-password-email.html', confirm_url=confirm_url),
                              sender='flaskemailbotf@gmail.com', )
                mail.send(message=msg)
                log_access_activity(f"Reset password instructions have been sent to '{email}'.")
                return render_template('verify-request.html')
            else:
                flash(f'Could not find account registered under email {email}.', 'danger')
        except RateLimitExceeded as e:
            log_access_activity(f"Rate limit exceeded for reset password of email {email}. Error: {e.description}")
            flash('Rate limit exceeded for sending reset password email. Try again later.', 'danger')
        except SMTPException as e:
            log_error(f"SMTPException: Error sending reset password email to '{email}': {str(e)}")
            flash("An error occurred while sending reset password email. Please try again later.", "danger")
        except Exception as e:
            log_error(f"Error generating reset password token for '{email}': {str(e)}")
            flash("An error occurred while processing your request. Please try again later.", "danger")
    else:
        flash("Invalid input of reset password email. Try again later.", "danger")
    return redirect(url_for('forgot_password_page'))


@limiter.limit("3 per minute", key_func=lambda: f"failed_login:{request.form.get('email')}",
               error_message='Failed send reset password email attempts.')
def check_reset_password_rate(email):
    log_access_activity(f"Attempt to send mail for reset password to '{email}'.")


@app.route('/confirm_reset_password/<token>')
def confirm_reset_password(token):
    try:
        valid, email = EmailAuthenticator.confirm_token(token)
        user = User.query.get(email)
        if user:
            if valid:
                return render_template('reset-password.html', email=email)
            else:
                flash("The reset password link has expired.", "danger")
        else:
            flash("The reset password link is invalid.", "danger")
    except Exception as e:
        log_error(f"An error occurred during reset password confirmation: {str(e)}")
        flash("An unexpected error occurred. Please try again later.", "danger")
    return redirect(url_for('forgot_password_page'))


@app.route('/reset_password', methods=['POST'])
def reset_password():
    try:
        email = request.form['email']
        user = User.query.get(email)
        if user:
            new_password = bcrypt.generate_password_hash(request.form['password'])
            user.password = new_password
            db.session.add(user)
            db.session.commit()
            log_access_activity(f"User with email '{email}' reset password successfully.")
            flash("You have reset your password successfully.", "success")
            return redirect(url_for('index'))
        else:
            flash("The user does not exist anymore.", "danger")
    except exc.SQLAlchemyError as e:
        db.session.rollback()
        log_error(f"Error during database transaction for reset password: {str(e)}")
        flash("An error occurred while processing your request. Please try again later.", "danger")
    except Exception as e:
        log_error(f"An unexpected error occurred: {str(e)}")
        flash("An unexpected error occurred. Please try again later.", "danger")
    return redirect(url_for('forgot_password_page'))


@app.route('/profile')
@login_required
def profile():
    email = current_user.email
    profile = Profile.query.get(email)
    return render_template('profile.html', profile=profile)


@app.route('/edit_profile', methods=['POST'])
@login_required
def edit_profile():
    try:
        check_edit_attempts()

        email = request.form.get('email', None)
        print(email)
        profile = Profile.query.get(email if email else current_user.email)
        profile.name = request.form.get('name', profile.name)
        profile.birth = request.form.get('birth', profile.birth)
        profile.ic = request.form.get('ic', profile.ic)
        profile.addr1 = request.form.get('addr1', profile.addr1)
        profile.addr2 = request.form.get('addr2', profile.addr2)
        profile.addr3 = request.form.get('addr3', profile.addr3)
        profile.phone = request.form.get('phone', profile.phone)

        def parse_date(date_string):
            return datetime.strptime(date_string, '%Y-%m-%d') if date_string else None

        profile.name = request.form.get('name', profile.name)
        profile.birth = request.form.get('birth', profile.birth)
        profile.ic = request.form.get('ic', profile.ic)
        profile.addr1 = request.form.get('addr1', profile.addr1)
        profile.addr2 = request.form.get('addr2', profile.addr2)
        profile.addr3 = request.form.get('addr3', profile.addr3)
        profile.phone = request.form.get('phone', profile.phone)

        # Set datetime attributes only if the corresponding form fields exist
        profile.first_public_serving_date = parse_date(request.form.get('firstServingDate'))
        profile.current_public_serving_date = parse_date(request.form.get('currentServingDate'))

        profile.service_name = request.form.get('serviceName', profile.service_name)
        profile.service_group = request.form.get('serviceGroup', profile.service_group)
        profile.grade = request.form.get('grade', profile.grade)
        profile.job = request.form.get('job', profile.job)
        profile.spouse_name = request.form.get('spouseName', profile.spouse_name)

        db.session.add(profile)
        db.session.commit()

        log_access_activity(f'Profile of email {profile.email} has been edited by {current_user.email}')
        flash("Information has been successfully saved!", 'success')
        return render_template('profile.html', profile=profile) if not email else redirect(request.referrer)
    except exc.SQLAlchemyError as e:
        db.session.rollback()
        log_error(f"SQLAlchemyError occurred while editing the profile: {str(e)}")
        flash("An unexpected error occurred. Please try again later.", "danger")
    except RateLimitExceeded as e:
        log_access_activity(
            f"Rate limit exceeded for edit profile attempts of email {current_user.email}. Error: {e.description}")
        flash('Rate limit exceeded for edit profile attempt. Try again later.', 'danger')
    except Exception as e:
        # Log any other unexpected exceptions
        log_error(f"An unexpected error occurred while editing the profile: {str(e)}")
        flash("An unexpected error occurred. Please try again later.", "danger")
    # Redirect to an error page or the previous page
    return redirect(request.referrer)


@limiter.limit("3 per minute", key_func=lambda: current_user.email, error_message='Too many attempts.')
def check_edit_attempts():
    log_access_activity(f"Edit profile attempt for user with email '{current_user.email}'.")


@app.route('/display_assets', methods=['GET'])
@login_required
def display_assets():
    email = current_user.email
    user_assets = {'revenues': [revenue.as_dict() for revenue in Revenue.query.filter_by(email=email).all()],
                   'expenses': [expense.as_dict() for expense in Expense.query.filter_by(email=email).all()],
                   'inventories': [inventory.as_dict() for inventory in Inventory.query.filter_by(email=email).all()]}
    user_assets_camel_case = convert_keys_to_camel_case(user_assets)
    return render_template('assets.html', user_assets=user_assets_camel_case, email=current_user.email)


def convert_keys_to_camel_case(dictionary):
    def to_camel_case(snake_str):
        components = snake_str.split('_')
        return components[0] + ''.join(x.title() for x in components[1:])

    if isinstance(dictionary, dict):
        return {to_camel_case(key): convert_keys_to_camel_case(value) for key, value in dictionary.items()}
    elif isinstance(dictionary, list):
        return [convert_keys_to_camel_case(item) for item in dictionary]
    else:
        return dictionary


@app.route('/validate_pdf', methods=['POST'])
@limit_content_length(2 * 1024 * 1024)
@login_required
def validate_pdf():
    result = False
    try:
        files = request.files
        file_bytes = list(files.values())[0].read()
        PdfReader(io.BytesIO(file_bytes), True)
        result = True
    except PyPdfError as e:
        log_error(f'Unable to parse the PDF bytes: {str(e)}')
        result = 'Invalid file format (required PDf format).'
    except Exception as e:
        log_error(f"An unexpected error occurred while validating pdf: {str(e)}")
        result = 'Expected error. Please refresh and try again.'
    return jsonify(result=result)


@app.errorhandler(413)
def files_too_large(e):
    log_error(f'File size too large: {str(e)}')
    return jsonify(result='File size must be equal or smaller than 2Mb.')


def update_from_dict(model_instance, data):
    # Skip if ID contains 'temp'
    if 'id' in data and 'temp' in data['id']:
        return
    # Update model fields based on data dictionary
    for key, value in data.items():
        # Skip if the key doesn't exist in the model_instance
        if not hasattr(model_instance, key):
            continue
        setattr(model_instance, key, value)


@app.route('/manage_assets', methods=['POST'])
@login_required
def manage_assets():
    try:
        check_manage_assets_rate()
        data = convert_keys_to_snake_case(
            json.loads(request.form.get('data').replace('"True"', 'true').replace('"False"', 'false')))
        files = request.files
        for category, value_list in data['add'].items():
            asset_class = eval(category.capitalize())
            for data_dict in value_list:
                add_or_update_asset(asset_class, data_dict,
                                    files.get(f'{asset_class.__tablename__}_file_{data_dict["id"]}'))

        for category, removeIds in data['delete'].items():
            asset_class = eval(category.capitalize())
            for removeId in removeIds:
                delete_asset(asset_class, str(removeId))

        log_access_activity(f"Email {current_user.email} has successfully managed assets.")
    except RateLimitExceeded as e:
        flash('Rate limit exceeded for manage asset. Try again later.', 'danger')
        log_access_activity(
            f"Rate limit exceeded for manage asset of email {current_user.email}. Error: {e.description}")
    return url_for('display_assets')


def add_or_update_asset(asset_class, item, file):
    asset = asset_class.query.get(item['id'])
    try:
        if asset:
            update_from_dict(asset, item)
        else:
            asset = asset_class(**item)
            asset.id = None
            db.session.add(asset)
        asset.approve_status = False
        db.session.commit()
        Path(f"asset_pdfs/{asset.email}").mkdir(exist_ok=True)
        type = str(asset_class.__tablename__)

        file_bytes = file.read()
        PdfReader(io.BytesIO(file_bytes))
        filename = secure_filename(f'{type}_{asset.id}.pdf')
        file = os.path.join(app.config['UPLOAD_FOLDER'], f'{asset.email}', filename)
        with open(file, 'wb') as f:
            f.write(file_bytes)
    except Exception as e:
        db.session.rollback()
        log_error(f"Error add/update item {asset}: {str(e)}")


def delete_asset(asset_class, id):
    try:
        asset = asset_class.query.get(id)
        if asset:
            db.session.delete(asset)
            type = str(asset_class.__table__.name).lower()
            filename = secure_filename(f'{type}_{asset.id}.pdf')
            file = os.path.join(app.config['UPLOAD_FOLDER'], f'{asset.email}', filename)
            db.session.commit()
            os.remove(file)
    except Exception as e:
        log_error(f"Error deleting item: {str(e)}")
        db.session.rollback()


@limiter.limit("3 per minute", key_func=lambda: current_user.email, error_message='Too many attempts.')
def check_manage_assets_rate():
    log_access_activity(f"Manage assets attempt for user with email '{current_user.email}'.")


def convert_keys_to_snake_case(dictionary):
    def to_snake_case(snake_str):
        return re.sub('([a-z0-9])([A-Z])', r'\1_\2', snake_str).lower()

    if isinstance(dictionary, dict):
        return {to_snake_case(key): convert_keys_to_snake_case(value) for key, value in dictionary.items()}
    elif isinstance(dictionary, list):
        return [convert_keys_to_snake_case(item) for item in dictionary]
    else:
        return dictionary


@app.route('/send_pdf', methods=['GET', 'POST'])
def send_pdf():
    filename = request.args.get('filename')
    email = request.args.get('email', None)
    user_dir = os.path.join(app.config['UPLOAD_FOLDER'], current_user.email if not email else email)
    if os.path.exists(os.path.join(user_dir, filename + '.pdf')):
        return send_from_directory(user_dir, filename + '.pdf', as_attachment=False)
    return 'Not exist'


@app.route('/get_print_assets', methods=['POST'])
@login_required
def get_print_assets():
    profile_detail = Profile.query.get(current_user.email)
    assets_json = request.get_json()
    print(assets_json)
    return render_template('print-assets.html', profile_detail=profile_detail, assets_json=assets_json)


@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if current_user.role != 'admin':
        logout_user()
        return redirect(request.referrer)
    revenues = convert_keys_to_camel_case([r.as_dict() for r in Revenue.query.all()])
    expenses = convert_keys_to_camel_case([e.as_dict() for e in Expense.query.all()])
    inventories = convert_keys_to_camel_case([i.as_dict() for i in Inventory.query.all()])
    profiles = convert_keys_to_camel_case(
        [{**User.query.get(p.email).as_dict(), **p.as_dict()} for p in Profile.query.all()])
    return render_template('admin-dashboard.html', revenues=revenues, expenses=expenses, inventories=inventories,
                           profiles=profiles, user=current_user)


@app.route('/delete_item', methods=['POST'])
@login_required
def delete_item():
    if current_user.role != 'admin':
        logout_user()
        return redirect(request.referrer)
    type = str(request.form.get('type'))
    type_class = {'revenue': Revenue, 'expense': Expense, 'inventory': Inventory, 'user': User}[type]
    delete_asset(type_class, request.form.get('id'))
    flash('The asset is successfully deleted', 'success')
    log_access_activity(f'The asset is successfully deleted by admin {current_user.email}')
    return redirect(url_for('admin_dashboard'))


@app.route('/approve_asset', methods=['GET', 'POST'])
@login_required
def approve_asset():
    if current_user.role != 'admin':
        logout_user()
        return redirect(request.referrer)
    try:
        type_class = eval(request.form.get('type').capitalize())
        asset = type_class.query.get(request.form.get('id'))
        asset.approve_status = True
        db.session.add(asset)
        db.session.commit()
        flash('The asset is successfully approved.', 'success')
        log_access_activity(f'The asset is successfully approved by admin {current_user.email}')
    except Exception as e:
        log_error(f"Error approve item: {str(e)}")
        db.session.rollback()
    return redirect(url_for('admin_dashboard'))


# Occasionally check database for unauthorized users and delete them
@scheduler.task('interval', id='check_token_expiration', seconds=3600)
def check_token_expiration():
    tokens_to_remove = []
    for token in tokens:
        token_valid, email = EmailAuthenticator.confirm_token(token)
        if not token_valid:
            expired_user = User.query.filter_by(email=email).first()
            if expired_user:
                expired_email = expired_user.email
                db.session.delete_asset(expired_user)
                db.session.commit()
                tokens_to_remove.append(token)
                log_access_activity(
                    f"User with email '{expired_email}' has been deleted due to an expired/invalid token.")
    # Remove expired/invalid tokens
    for token in tokens_to_remove:
        tokens.remove(token)
