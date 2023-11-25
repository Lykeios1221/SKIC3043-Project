import json
from datetime import datetime
from smtplib import SMTPException

from flask import render_template, request, flash, url_for, redirect
from flask_apscheduler import APScheduler
from flask_bcrypt import Bcrypt
from flask_limiter import Limiter, RateLimitExceeded
from flask_limiter.util import get_remote_address
from flask_login import LoginManager, current_user, login_user, login_required, logout_user
from flask_mail import Mail, Message
from sqlalchemy import exc

from Logging import log_access_activity, log_error
from Model import User, db, EmailAuthenticator, Profile, Revenue, Expense, Inventory, LoginForm, SignupForm, \
    ResetPasswordForm
from app import app

bcrypt = Bcrypt(app)
mail = Mail(app)

scheduler = APScheduler(app=app)
scheduler.start()

login_manager = LoginManager(app)

tokens = []

limiter = Limiter(
    app=app,
    key_func=lambda: current_user.email,
    storage_uri="memory://",
)


@login_manager.user_loader
def user_loader(user_email):
    return User.query.get(user_email)


@app.route('/')
def index():
    logout_user()
    login_form = LoginForm()
    sign_up_form = SignupForm()
    return render_template('login.html', login_form=login_form, sign_up_form=sign_up_form)


@app.route('/login', methods=['POST'])
def login():
    logout_user()
    form = LoginForm()
    # Validate form input
    if form.validate_on_submit():
        email = form.login_email.data
        password = form.login_password.data
        check_login_attempts_for_ip(email);
        try:
            user = User.query.filter_by(email=email).first()
            if user and user.authorized_status == 1 and not bcrypt.check_password_hash(user.password, password):
                rate_limited_login_attempt(email)
            if user and bcrypt.check_password_hash(user.password, password) and user.authorized_status == 1:
                log_access_activity(f"User '{user.username}' with email '{email}' has logged in.")
                login_user(user)
                flash(f'Welcome back, User {user.username}', 'success')
                return redirect(url_for('display_assets'))
            else:
                flash('Invalid credentials for login. Please try again.', 'danger')
        except RateLimitExceeded as e:
            log_access_activity(f"Rate limit exceeded for login attempts of email {email}. Error: {e.description}")
            flash('Rate limit exceeded for login attempt. Try again later.', 'danger')
    else:
        # Form validation failed
        flash('Invalid login attempt. Please check your credentials and try again.', 'danger')

    return redirect(url_for('index'))


@limiter.limit("10 per minute", key_func=get_remote_address, error_message='Too many attempts.')
def check_login_attempts_for_ip(email):
    log_access_activity(f"Login attempt for user with email '{email}'.")


@limiter.limit("3 per minute", key_func=get_remote_address, error_message='Too many attempts.')
def check_signup_attempts_for_ip(email):
    log_access_activity(f"Sign-up attempt with email '{email}'.")


@limiter.limit("3 per minute", key_func=lambda: f"failed_login:{request.form.get('email')}",
               error_message='Failed login attempts.')
def rate_limited_login_attempt(email):
    log_access_activity(f"Failed login attempt for user with email '{email}'.")


@app.route('/signup', methods=['POST'])
def signup():
    form = SignupForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.signup_email.data
        password = form.signup_password.data
        print(email)
        check_signup_attempts_for_ip(email)
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        try:
            new_user = User(username=name, email=email, password=hashed_password, authorized_status=0)
            db.session.add(new_user)
            db.session.commit()

            token = EmailAuthenticator.generate_token(email)
            tokens.append(token)
            confirm_url = url_for("confirm_email", token=token, _external=True)
            subject = "SKIC: Please confirm your email"
            msg = Message(
                subject,
                recipients=[email],
                html=render_template('verification_email.html', confirm_url=confirm_url),
                sender='flaskemailbotf@gmail.com',
            )
            print('send')
            mail.send(message=msg)
            print('success')
            log_access_activity(f"User '{name}' signed up with email '{email}'. Verification email sent.")
            return render_template('VerifyRequest.html')
        except exc.IntegrityError as e:
            log_error(f"IntegrityError: {str(e)}")
            flash("An unexpected error occurred. Try again later.", 'danger')
        except exc.SQLAlchemyError as e:
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


@app.route('/forgot_password_page')
def forgot_password_page():
    form = ResetPasswordForm()
    return render_template('forgot_password.html', form=form)


@limiter.limit("3 per minute", key_func=lambda: f"failed_login:{request.form.get('email')}",
               error_message='Failed send reset password email attempts.')
def check_reset_password_rate(email):
    log_access_activity(f"Attempt to send mail for reset password to '{email}'.")


@app.route('/send_reset_email', methods=['POST'])
def send_reset_email():
    form = ResetPasswordForm()
    if form.validate_on_submit():
        try:
            email = request.form['email']
            check_reset_password_rate(email)

            try:
                token = EmailAuthenticator.generate_token(email)
                tokens.append(token)
                confirm_url = url_for("reset_password", token=token, _external=True)
                subject = "SKIC: Request for reset password"

                try:
                    msg = Message(
                        subject,
                        recipients=[email],
                        html=render_template('reset_password_email.html', confirm_url=confirm_url),
                        sender='flaskemailbotf@gmail.com',
                    )
                    mail.send(message=msg)
                    log_access_activity(f"Reset password instructions have been sent to '{email}'.")
                    return render_template('VerifyRequest.html')
                except SMTPException as e:
                    log_error(f"SMTPException: Error sending reset password email to '{email}': {str(e)}")
                    flash("An error occurred while sending reset password email. Please try again later.", "danger")
                    return redirect(url_for('index'))

            except Exception as e:
                log_error(f"Error generating reset password token for '{email}': {str(e)}")
                flash("An error occurred while processing your request. Please try again later.", "danger")
                return redirect(url_for('index'))

        except RateLimitExceeded as e:
            log_access_activity(f"Rate limit exceeded for reset password of email {email}. Error: {e.description}")
            flash('Rate limit exceeded for sending reset password email. Try again later.', 'danger')
            return redirect(url_for('index'))
    else:
        flash("Invalid input of reset password email. Try again later.", "danger")
        return redirect(url_for('index'))


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
                log_access_activity(
                    f"Email '{email}' registered failed due to waiting for verification")
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
            try:
                if valid:
                    user.authorized_status = 1
                    profile = Profile(email=email)
                    db.session.add(user)
                    db.session.commit()
                    db.session.add(profile)
                    db.session.commit()
                    login_user(user)
                    log_access_activity(f"User with email '{email}' is verified.")
                    flash("You have confirmed your account. Thanks!", "success")
                    return redirect(url_for('profile'))
                else:
                    db.session.delete(user)
                    db.session.commit()
                    flash("The confirmation link has expired.", "danger")
            except exc.SQLAlchemyError as e:
                log_error(f"Error during database transaction for confirm email.: {str(e)}")
                flash("An error occurred while processing your request. Please try again later.", "danger")
                return redirect(url_for('index'))
        else:
            flash("The confirmation link is invalid.", "danger")

    except Exception as e:
        log_error(f"An error occurred during email confirmation: {str(e)}")
        flash("An unexpected error occurred. Please try again later.", "danger")

    return redirect(url_for('index'))


@app.route("/reset_password/<token>", methods=['GET', 'POST'])
def reset_password(token):
    try:
        if request.method == 'GET':
            try:
                valid, email = EmailAuthenticator.confirm_token(token)
                user = User.query.filter_by(email=email).first()

                if user:
                    try:
                        if valid:
                            return render_template('reset_password.html', token=token, email=email)
                        else:
                            flash("The reset password link has expired.", "danger")
                    except Exception as e:
                        log_error(f"Error rendering reset password form: {str(e)}")
                        flash("An error occurred while processing your request. Please try again later.", "danger")
                else:
                    flash("The confirmation link is invalid.", "danger")
            except Exception as e:
                log_error(f"Error confirming reset password token: {str(e)}")
                flash("An unexpected error occurred. Please try again later.", "danger")

        elif request.method == 'POST':
            try:
                email = request.form['email']
                new_password = request.form['password']
                new_password = bcrypt.generate_password_hash(new_password)
                user = User.query.filter_by(email=email).first()

                if user:
                    try:
                        user.password = new_password
                        db.session.add(user)
                        db.session.commit()
                        log_access_activity(f"User with email '{email}' reset password successfully.")
                        flash("You have reset your password successfully.", "success")
                    except exc.SQLAlchemyError as e:
                        log_error(f"Error during database transaction for reset password: {str(e)}")
                        flash("An error occurred while processing your request. Please try again later.", "danger")
                else:
                    flash("The user does not exist.", "danger")
            except Exception as e:
                log_error(f"An unexpected error occurred: {str(e)}")
                flash("An unexpected error occurred. Please try again later.", "danger")

    except Exception as e:
        log_error(f"An unexpected error occurred: {str(e)}")
        flash("An unexpected error occurred. Please try again later.", "danger")

    return redirect(url_for('index'))


@app.route('/profile')
@login_required
def profile():
    email = current_user.email
    profile = Profile.query.get(email)
    return render_template('profile.html', profile=profile)


@limiter.limit("5 per minute", key_func=lambda: current_user.email, error_message='Too many attempts.')
def check_edit_attempts():
    log_access_activity(f"Edit profile attempt for user with email '{current_user.email}'.")


@app.route('/edit_profile', methods=['POST'])
@login_required
def edit_profile():
    try:

        check_edit_attempts()
        name = request.form['name']
        birth = request.form['birth']
        ic = request.form['ic']
        addr1 = request.form['addr1']
        addr2 = request.form['addr2']
        addr3 = request.form['addr3']
        phone = request.form['phone']
        first_public_serving_date = datetime.strptime(request.form['firstServingDate'], '%Y-%m-%d')
        current_public_serving_date = datetime.strptime(request.form['currentServingDate'], '%Y-%m-%d')
        service_name = request.form['serviceName']
        service_group = request.form['serviceGroup']
        grade = request.form['grade']
        job = request.form['job']
        spouse_name = request.form['spouseName']

        # Create a new Profile instance
        profile = Profile.query.get(current_user.email)
        profile.name = name
        profile.birth = birth
        profile.ic = ic
        profile.addr1 = addr1
        profile.addr2 = addr2
        profile.addr3 = addr3
        profile.phone = phone
        profile.first_public_serving_date = first_public_serving_date
        profile.current_public_serving_date = current_public_serving_date
        profile.service_name = service_name
        profile.service_group = service_group
        profile.grade = grade
        profile.job = job
        profile.spouse_name = spouse_name

        db.session.add(profile)
        db.session.commit()
        flash("Information has been successfully saved!", 'success')
        log_access_activity(f'Profile of email{current_user.email} has been edited')
        return render_template('profile.html', profile=profile)

    except exc.SQLAlchemyError as sql_err:
        db.session.rollback()
        log_error(f"SQLAlchemyError occurred while editing the profile: {str(sql_err)}")
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
    return redirect(url_for('profile'), profile)


@app.route('/display_assets', methods=['GET'])
@login_required
def display_assets():
    email = current_user.email
    individual_revenues = Revenue.query.filter_by(email=email, type='Individual').all()
    house_revenues = Revenue.query.filter_by(email=email, type='Household').all()
    revenues = Revenue.query.filter_by(email=email).all()
    individual_expenses = Expense.query.filter_by(email=email, type='Individual').all()
    house_expenses = Expense.query.filter_by(email=email, type='Household').all()
    expenses = Expense.query.filter_by(email=email).all()
    inventories = Inventory.query.filter_by(email=email).all()
    user_assets = {'revenues': [revenue.as_dict() for revenue in revenues],
                   'expenses': [expense.as_dict() for expense in expenses],
                   'inventories': [inventory.as_dict() for inventory in inventories]}
    user_assets_camel_case = convert_keys_to_camel_case(user_assets)
    user_assets_json = json.dumps(user_assets_camel_case)
    return render_template('assetdeclaration.html', indRevenues=individual_revenues, houseRevenues=house_revenues,
                           revenues=revenues, indExpenses=individual_expenses, houseExpenses=house_expenses,
                           expenses=expenses, inventories=inventories, user_assets_json=user_assets_json,
                           email=current_user.email)


@limiter.limit("5 per minute", key_func=lambda: current_user.email, error_message='Too many attempts.')
def check_manage_assets_rate():
    log_access_activity(f"Manage assets attempt for user with email '{current_user.email}'.")


@app.route('/manage_assets', methods=['POST'])
def manage_assets():
    try:
        check_manage_assets_rate()
        print('maanage')
        data = request.get_json()
        print(data)
        # Handle revenues additions and modifications
        for item in data.get('revenuesChanges', {}).get('additions', []):
            print('in')
            add_or_update_revenue(item)

        for item in data.get('revenuesChanges', {}).get('modifications', []):
            add_or_update_revenue(item)

        for item in data.get('revenuesChanges', {}).get('deletions', []):
            delete_revenue(item)

        # Handle expenses additions and modifications
        for item in data.get('expensesChanges', {}).get('additions', []):
            add_or_update_expense(item)

        for item in data.get('expensesChanges', {}).get('modifications', []):
            add_or_update_expense(item)

        for item in data.get('expensesChanges', {}).get('deletions', []):
            delete_expense(item)

        # Handle inventories additions, modifications, and deletions
        for item in data.get('inventoriesChange', {}).get('additions', []):
            add_or_update_inventory(item)

        for item in data.get('inventoriesChange', {}).get('modifications', []):
            add_or_update_inventory(item)

        for item in data.get('inventoriesChange', {}).get('deletions', []):
            delete_inventory(item)

        log_access_activity(f"Email {current_user.email} has successfully managed assets.")
        return url_for('display_assets')
        # return jsonify({"message": "Operation completed successfully"}), 200

    except RateLimitExceeded as e:
        flash('Rate limit exceeded for manage asset. Try again later.', 'danger')
        log_access_activity(f"Rate limit exceeded for manage asset of email {current_user.email}. Error: {e.description}")
        return url_for('display_assets')


def add_or_update_revenue(item):
    try:
        print(item)
        revenue = Revenue.query.get(item['id'])
        if revenue:
            # Update existing revenue
            update_from_dict(revenue, item)
        else:
            # Add new revenue
            new_revenue = Revenue(**item)
            new_revenue.id = None
            db.session.add(new_revenue)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        log_error(f"Error add/update revenue item: {str(e)}")


def delete_revenue(item):
    try:
        revenue = Revenue.query.get(item['id'])
        if revenue:
            db.session.delete(revenue)
            db.session.commit()
    except Exception as e:
        log_error(f"Error deleting revenue item: {str(e)}")
        db.session.rollback()


def add_or_update_expense(item):
    try:
        expense = Expense.query.get(item['id'])
        if expense:
            # Update existing expense
            update_from_dict(expense, item)
        else:
            # Add new expense
            new_expense = Expense(**item)
            new_expense.id = None
            db.session.add(new_expense)
        db.session.commit()
    except Exception as e:
        log_error(f"Error add/update expense item: {str(e)}")
        db.session.rollback()


def delete_expense(item):
    try:
        expense = Expense.query.get(item['id'])
        if expense:
            db.session.delete(expense)
            db.session.commit()
    except Exception as e:
        log_error(f"Error deleting expense item: {str(e)}", exc_info=True)
        db.session.rollback()


def add_or_update_inventory(item):
    try:
        inventory = Inventory.query.get(item['id'])
        if inventory:
            # Update existing inventory
            update_from_dict(inventory, item)
        else:
            # Add new inventory
            new_inventory = Inventory(**item)
            new_inventory.id = None
            db.session.add(new_inventory)
        db.session.commit()
    except Exception as e:
        log_error(f"Error add/update inventory item: {str(e)}")
        db.session.rollback()


def delete_inventory(item):
    try:
        inventory = Inventory.query.get(item['id'])
        if inventory:
            db.session.delete(inventory)
            db.session.commit()
    except Exception as e:
        log_error(f"Error deleting inventory item: {str(e)}")
        db.session.rollback()


@app.route('/get_print_assets', methods=['POST'])
def get_print_assets():
    profile_detail = Profile.query.get(current_user.email)
    assets_json = request.get_json()
    inventory = assets_json['inventory']
    revenue = assets_json['revenue']
    expense = assets_json['expense']
    return render_template('print_assets.html', profile_detail=profile_detail, inventory=inventory, expense=expense,
                           revenue=revenue)


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


@scheduler.task('interval', id='check_token_expiration', seconds=600)
def check_token_expiration():
    tokens_to_remove = []
    for token in tokens:
        token_valid, email = EmailAuthenticator.confirm_token(token)

        if not token_valid:
            expired_user = User.query.filter_by(email=email).first()

            if expired_user:
                expired_email = expired_user.email
                db.session.delete(expired_user)
                db.session.commit()
                tokens_to_remove.append(token)
                log_access_activity(
                    f"User with email '{expired_email}' has been deleted due to an expired/invalid token.")

    # Remove expired/invalid tokens
    for token in tokens_to_remove:
        tokens.remove(token)


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
