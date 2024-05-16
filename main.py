from flask import Flask, render_template, redirect, url_for, session, flash
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Email, ValidationError
import bcrypt
from flaskext.mysql import MySQL
import mysql.connector

app = Flask(__name__)

mydb = mysql.connector.connect(
  host="localhost",
  user="root",
  password="",
  database="supplychain"
)

# print(mydb)
mycursor = mydb.cursor()

mycursor.execute("SHOW TABLES")

for x in mycursor:
  print(x)


# MySQL Configuration
# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://'
# app.config['MYSQL_HOST'] = 'localhost'
# app.config['MYSQL_USER'] = 'root'
# app.config['MYSQL_PASSWORD'] = ''
# app.config['MYSQL_DB'] = 'supplychain'
app.secret_key = 'your_secret_key_here'
# mysql = MySQL(app)
# mysql.init_app(app)

# import pymysql

# # Replace with your credentials
# host = 'localhost'
# user = 'danielfori'
# password = ''
# database = 'users'
#
# try:
#     connection = pymysql.connect()
#     print("Connection successful!")
#
# except pymysql.err.OperationalError as err:
#     print("Error connecting to MySQL server:", err)

# finally:
#     if connection:
#         connection.close()
#         print("Connection closed.")




class RegisterForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired()])
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    role = StringField("Role", validators=[DataRequired()])
    submit = SubmitField("Register")

    def validate_email(self, field):
        mycursor = mydb.cursor()
        mycursor.execute("SELECT * FROM users where email=%s", (field.data,))
        user = mycursor.fetchone()
        mycursor.close()
        if user:
            raise ValidationError('Email Already Taken')


class LoginForm(FlaskForm):
    email = StringField("Email", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    role = StringField("Role", validators=[DataRequired()])
    submit = SubmitField("Login")


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        name = form.name.data
        email = form.email.data
        password = form.password.data
        role = form.role.data

        if role == 'admin':
            print(role)
        elif role == 'manufacturer':
            print(role)
        else:
            print('invalid role')
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
        mycursor = mydb.cursor()
        sql = "INSERT INTO users (name, email, password, role) VALUES (%s, %s, %s, %s)"
        val = (name, email, hashed_password, role)
        mycursor.execute(sql, val)

        mydb.commit()

        print(mycursor.rowcount, "record inserted.")
        print("1 record inserted, ID:", mycursor.lastrowid)


        # store data into database 
        # # mycursor = mydb.cursor()
        # mycursor.execute("INSERT INTO users (name,email,password,role) VALUES (%s,%s,%s,%s)",
        #                (name, email, hashed_password, role))
        # mysql.connection.commit()
        # mydb.commit()
        mycursor.close()

        return redirect(url_for('dashboard'))

    return render_template('register.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        email = form.email.data
        password = form.password.data
        role = form.role.data

        if role == 'admin':
            print(role)
        elif role == 'manufacturer':
            print(role)
        else:
            print('invalid role')


        mycursor.execute("SELECT * FROM users WHERE email=%s", (email,))
        user = mycursor.fetchone()
        # mycursor.close()
        if user and bcrypt.checkpw(password=password.encode('utf-8'), hashed_password=user[4].encode('utf-8')):
            session['user_id'] = user[0]
            return redirect(url_for('dashboard'))
        else:
            flash("Login failed. Please check your email and password")
            return redirect(url_for('login'))

    return render_template('login.html', form=form)


@app.route('/dashboard')
def dashboard():
    if 'user_id' in session:
        user_id = session['user_id']

        mycursor.execute("SELECT * FROM users where id=%s", (user_id,))
        user = mycursor.fetchone()
        mycursor.close()

        if user:
            return render_template('dashboard.html', user=user)

    return redirect(url_for('login'))


@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("You have been logged out successfully.")
    return redirect(url_for('login'))


if __name__ == '__main__':
    app.run(debug=True)