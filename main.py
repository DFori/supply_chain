from flask import Flask, render_template, redirect, url_for, session, flash, request
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
roles = ["admin", "manufacturer", "retailer", "delivery", ]

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

########################################## GEMINI #################################################################


# Get all users
def get_users():
    mycursor.execute("SELECT * FROM users")
    users = mycursor.fetchall()
    return users

# Add a new user
def add_user(username, email, role, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    mycursor.execute("INSERT INTO users (name, email, role, password) VALUES (%s, %s, %s, %s)", (username, email, role, hashed_password))
    mydb.commit()
    flash("User added successfully!", "success")

# Get user by ID for editing
def get_user(user_id):
    mycursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = mycursor.fetchone()
    return user

# Update user information
def update_user(user_id, username, email, role, password):
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    mycursor.execute("UPDATE users SET name = %s, email = %s, role = %s, password = %s WHERE id = %s;", (username, email, role, hashed_password, user_id))
    mydb.commit()
    flash("User information updated!", "success")

# Delete a user
def delete_user(user_id):
    mycursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
    mydb.commit()
    flash("User deleted!", "success")

# Admin dashboard route

@app.route("/admin")
def admin_dashboard():
    users = get_users()
    return render_template("admin_dashboard.html", users=users)

# Add user route
@app.route("/admin/add_user", methods=["GET", "POST"])
def add_user_form():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        role = request.form["role"]
        password = request.form["password"]
        add_user(username, email, role, password)
        return redirect(url_for("admin_dashboard"))
    return render_template("add_user.html")

# Edit user route
@app.route("/admin/edit_user/<int:user_id>", methods=["GET", "POST"])
def edit_user_form(user_id):
    user = get_user(user_id)
    if not user:
        flash("User not found!", "danger")
        return redirect(url_for("admin_dashboard"))
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        role = request.form["role"]
        password = request.form["password"]
        update_user(user_id, username, email, role, password)
        return redirect(url_for("admin_dashboard"))
    return render_template("edit_user.html", user=user)

# Delete user route
@app.route("/admin/delete_user/<int:user_id>", methods=["GET", "POST"])
def delete_user_confirmation(user_id):
    user = get_user(user_id)
    if not user:
        flash("User not found!", "danger")
        return redirect(url_for("admin_dashboard"))
    if request.method == "POST":
        delete_user(user_id)
        return redirect(url_for("admin_dashboard"))
    return render_template

####################### END GEMINI ###############################################
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
            if role == "admin":
                return render_template("admin_dashboard.html", users=get_users())
            else:
                return render_template("dashboard.html")
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