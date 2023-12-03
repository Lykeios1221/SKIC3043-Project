from flask_login import UserMixin
from flask_sqlalchemy import SQLAlchemy
from flask_wtf.recaptcha import RecaptchaField
from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import InputRequired, DataRequired, Regexp, Email
from flask_wtf import FlaskForm
# import email_validator

from app import app

db = SQLAlchemy(app)

with app.app_context():
    db.create_all()


class User(UserMixin, db.Model):
    username = db.Column(db.String(255), unique=False, nullable=False)
    email = db.Column(db.String(255), primary_key=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    authorized_status = db.Column(db.Integer, nullable=False)

    def __repr__(self):
        return f"User('{self.email}', '{self.username}')"

    def get_id(self):
        return self.email


class Profile(db.Model):
    email = db.Column(db.String(255), primary_key=True)
    name = db.Column(db.String(255))
    birth = db.Column(db.Date)
    ic = db.Column(db.String(255))
    addr1 = db.Column(db.String(255))
    addr2 = db.Column(db.String(255))
    addr3 = db.Column(db.String(255))
    phone = db.Column(db.String(15))
    first_public_serving_date = db.Column(db.Date)
    current_public_serving_date = db.Column(db.Date)
    service_name = db.Column(db.String(255))
    service_group = db.Column(db.String(255))
    grade = db.Column(db.String(255))
    job = db.Column(db.String(255))
    spouse_name = db.Column(db.String(255))

    def __repr__(self):
        return f"<Profile(email_index={self.email_index}, service_name={self.service_name}, job={self.job})>"

    def as_dict(self):
        return {column.name: str(getattr(self, column.name)) for column in self.__table__.columns}


class Revenue(db.Model):
    email = db.Column(db.String(255), nullable=False)
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    description = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(255), nullable=False)
    total = db.Column(db.Numeric(19, 2), nullable=False)
    approve_status = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return (f"<Revenue(id={self.id}, email={self.email}, description={self.description}, type={self.type}, "
                f"total={self.total}, approve_status={self.approve_status})>")

    def as_dict(self):
        return {column.name: str(getattr(self, column.name)) for column in self.__table__.columns}


class Expense(db.Model):
    email = db.Column(db.String(255), nullable=False)
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    description = db.Column(db.String(255), nullable=False)
    type = db.Column(db.String(255), nullable=False)
    monthly_deduction = db.Column(db.Numeric(19, 2), nullable=False)
    total = db.Column(db.Numeric(19, 2), nullable=False)
    approve_status = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f"<Expense(id={self.id}, email={self.email}, description={self.description}, type={self.type}, " \
               f"monthly_deduction={self.monthly_deduction}, total={self.total}, approve_status={self.approve_status})>"

    def as_dict(self):
        return {column.name: str(getattr(self, column.name)) for column in self.__table__.columns}


class Inventory(db.Model):
    email = db.Column(db.String(255), nullable=False)
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    type = db.Column(db.String(255), nullable=False)
    owner = db.Column(db.String(255), nullable=False)
    inv_description = db.Column(db.String(255), nullable=False)
    reg_certificate_no = db.Column(db.Integer, nullable=False)
    date_of_ownership = db.Column(db.String(10), nullable=False)
    quantity_amount = db.Column(db.Integer, nullable=False)
    ownership_size = db.Column(db.Integer, nullable=False)
    quantity_size = db.Column(db.Integer, nullable=False)
    acquisition_cost = db.Column(db.Numeric(19, 2), nullable=False)
    estimated_current_value = db.Column(db.Numeric(19, 2), nullable=False)
    method_of_acquisition = db.Column(db.String(255), nullable=False)
    approve_status = db.Column(db.Boolean, nullable=False, default=False)

    def __repr__(self):
        return f"<Inventory(id={self.id}, email={self.email}, type={self.type}, owner={self.owner}, " \
               f"inv_description={self.inv_description}, reg_certificate_no={self.reg_certificate_no}, " \
               f"date_of_ownership={self.date_of_ownership}, quantity_amount={self.quantity_amount}, " \
               f"ownership_size={self.ownership_size}, quantity_size={self.quantity_size}, " \
               f"acquisition_cost={self.acquisition_cost}, estimated_current_value={self.estimated_current_value}, " \
               f"method_of_acquisition={self.method_of_acquisition}, approve_status={self.approve_status})>"

    def as_dict(self):
        return {column.name: str(getattr(self, column.name)) for column in self.__table__.columns}


class LoginForm(FlaskForm):
    login_email = StringField('Email', validators=[InputRequired()])
    login_password = PasswordField('Password', validators=[InputRequired()])
    recaptcha = RecaptchaField()

    def __repr__(self):
        return (f"<LoginForm(login_email={self.login_email.data}, login_password={self.login_password.data}, "
                f"recaptcha={self.recaptcha.data})>")


class SignupForm(FlaskForm):
    name = StringField('Name', validators=[InputRequired()])
    signup_email = StringField('Email', validators=[InputRequired(), Email()])
    signup_password = PasswordField('Password', validators=[InputRequired(),
        Regexp(r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$',
            message="Password must include at least one uppercase and one lowercase letter, "
                    "contain at least one special character and one digit number, "
                    "and be between 8 to 20 characters in length.")])
    recaptcha = RecaptchaField()

    def __repr__(self):
        return f"<SignupForm(name={self.name.data}, signup_email={self.signup_email.data}, " \
               f"signup_password={self.signup_password.data}, recaptcha={self.recaptcha.data})>"


class ResetPasswordForm(FlaskForm):
    email = StringField('Email', validators=[InputRequired(), Email()])
    recaptcha = RecaptchaField()


class EmailAuthenticator:

    @staticmethod
    def generate_token(email):
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        return serializer.dumps(email, salt=app.config["SECURITY_PASSWORD_SALT"])

    @staticmethod
    def confirm_token(token, expiration=3600):
        serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
        try:
            email = serializer.loads(token, salt=app.config["SECURITY_PASSWORD_SALT"], max_age=expiration)
            return True, email
        except (SignatureExpired, BadSignature):
            email = serializer.loads(token, salt=app.config["SECURITY_PASSWORD_SALT"])
            return False, email
