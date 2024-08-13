from flask import Flask, request, render_template, redirect, url_for, session, flash
from flask_mail import Mail, Message
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField
from wtforms.validators import DataRequired, Email, Length
import pymysql
import random
import string
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_secret_key'  # 用于保存会话信息

# 配置 MySQL
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'your_mysql_user'
app.config['MYSQL_PASSWORD'] = 'your_mysql_password'
app.config['MYSQL_DB'] = 'mydatabase'

# 初始化 MySQL 数据库连接
import pymysql.cursors

def get_db_connection():
    return pymysql.connect(
        host=app.config['MYSQL_HOST'],
        user=app.config['MYSQL_USER'],
        password=app.config['MYSQL_PASSWORD'],
        database=app.config['MYSQL_DB'],
        cursorclass=pymysql.cursors.DictCursor
    )

# 配置邮件发送服务（QQ邮箱和Gmail）
mail = Mail(app)

def configure_mail(service):
    """根据用户选择的邮箱服务动态配置邮件发送服务"""
    if service == 'qq':
        app.config['MAIL_SERVER'] = 'smtp.qq.com'
        app.config['MAIL_PORT'] = 465
        app.config['MAIL_USE_SSL'] = True
        app.config['MAIL_USERNAME'] = 'your_qq_email@qq.com'
        app.config['MAIL_PASSWORD'] = 'your_qq_email_password'
    elif service == 'gmail':
        app.config['MAIL_SERVER'] = 'smtp.gmail.com'
        app.config['MAIL_PORT'] = 465
        app.config['MAIL_USE_SSL'] = True
        app.config['MAIL_USERNAME'] = 'your_gmail_email@gmail.com'
        app.config['MAIL_PASSWORD'] = 'your_gmail_password'
    mail.init_app(app)

def generate_verification_code(length=6):
    """生成随机验证码"""
    return ''.join(random.choices(string.ascii_uppercase + string.digits, k=length))

class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=35)])
    email_service = SelectField('Select Email Service:', choices=[('qq', 'QQ Email'), ('gmail', 'Gmail')], validators=[DataRequired()])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6, max=35)])
    submit = SubmitField('Login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        email = form.email.data
        password = form.password.data
        email_service = form.email_service.data

        # 配置邮件服务
        configure_mail(email_service)

        # 生成验证码
        code = generate_verification_code()
        session['verification_code'] = code
        session['email'] = email
        session['username'] = username
        session['password'] = password

        # 发送验证码
        msg = Message('Your Verification Code', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Your verification code is: {code}'
        try:
            mail.send(msg)
            return redirect(url_for('verify'))
        except Exception as e:
            flash('Failed to send verification email. Please try again.')
            print(e)

    return render_template('register.html', form=form)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    if request.method == 'POST':
        code = request.form['code']
        if code == session.get('verification_code'):
            # 获取注册信息
            username = session.get('username')
            email = session.get('email')
            password = session.get('password')

            # 加密密码
            hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

            # 保存用户信息到数据库
            connection = get_db_connection()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)",
                                   (username, email, hashed_password))
                    connection.commit()
            finally:
                connection.close()

            return 'Email verified and user registered successfully!'
        else:
            return 'Invalid verification code, please try again.'

    return render_template('verify.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        # 验证用户信息
        connection = get_db_connection()
        try:
            with connection.cursor() as cursor:
                cursor.execute("SELECT password FROM users WHERE username=%s", (username,))
                result = cursor.fetchone()
                if result and bcrypt.checkpw(password.encode('utf-8'), result['password'].encode('utf-8')):
                    return 'Login successful!'
                else:
                    flash('Invalid username or password. Please try again.')
        finally:
            connection.close()

    return render_template('login.html', form=form)

if __name__ == '__main__':
    app.run(debug=True)
