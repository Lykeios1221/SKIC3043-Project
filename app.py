from flask import Flask

app = Flask(__name__, static_folder='static')
app.secret_key = 'secure_software'
app.config['SECURITY_PASSWORD_SALT'] = 'skic3043'
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://root@localhost/secure_software'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SCHEDULER_API_ENABLED'] = True

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 465
app.config['MAIL_USERNAME'] = 'flaskemailbotf@gmail.com'
app.config['MAIL_PASSWORD'] = 'ytiy ggna gzqj fkrk'
app.config['MAIL_USE_TLS'] = False
app.config['MAIL_USE_SSL'] = True

app.config['RECAPTCHA_PUBLIC_KEY'] = '6LctxBQpAAAAAPWXDeszLc6JdfN4qzWJEFEh4bB4'
app.config['RECAPTCHA_PRIVATE_KEY'] = '6LctxBQpAAAAABurREhgk1Uh_iRYIQlNX2bbkzGz'
app.config['RECAPTCHA_OPTIONS'] = {'theme': 'white'}

app.config["SESSION_PERMANENT"] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 120
app.config['SESSION_REFRESH_EACH_REQUEST'] = True

# app.config['UPLOAD_FOLDER'] = 'cache'
app.config['UPLOAD_EXTENSIONS'] = ['pdf']
app.config['UPLOAD_FOLDER'] = 'asset_pdfs'


import api
