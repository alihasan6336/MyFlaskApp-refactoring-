from flask import Flask, render_template, url_for, redirect, session, request, send_file, jsonify
from flask_mysqldb import MySQL
from passlib.hash import sha256_crypt
from functools import wraps
import csv
import os
from io import BytesIO

import pytz
from pytz import timezone
import tzlocal
from datetime import timedelta


app = Flask(__name__)

app.config['SESSION_TYPE'] = 'filesystem'
app.secret_key = os.environ['SECRET_KEY'] if 'DB_USER' in os.environ else "secret_123"

@app.before_request
def make_session_permanent():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=365)


# Config the database.
if 'DB_USER' in os.environ :
    app.config["MYSQL_HOST"] = os.environ['DB_HOST']
    app.config["MYSQL_USER"] = os.environ['DB_USER']
    app.config["MYSQL_PASSWORD"] = os.environ['DB_PASSWORD']
    app.config["MYSQL_DB"] = os.environ['DB_NAME']
    app.config["MYSQL_CURSORCLASS"] = "DictCursor"
else :
    app.config["MYSQL_HOST"] = "localhost"
    app.config["MYSQL_USER"] = "root"
    app.config["MYSQL_PASSWORD"] = "01019056677"
    app.config["MYSQL_DB"] = "passiontest"
    app.config["MYSQL_CURSORCLASS"] = "DictCursor"

mysql = MySQL(app)


# Define a function to get selection result from database.
def SearchInTheDatabase(executeString):

    # Start connection with the database.
    cur = mysql.connection.cursor()

    # Select from the database.
    selectionResults = cur.execute(executeString)

    # Close the connection with the database.
    cur.close()

    return selectionResults


# Define a function to get selection result from database with value.
def SearchInTheDatabaseWithValue(executeString, value):

    # Start connection with the database.
    cur = mysql.connection.cursor()

    # Select from the database.
    selectionResults = cur.execute(executeString, value)

    # Close the connection with the database.
    cur.close()

    return selectionResults


# Define a function to fetch data from the database.
def FetchFromTheDatabse(executeString):

    # Start connection with the database.
    cur = mysql.connection.cursor()

    # Fetch from the database.
    cur.execute(executeString)
    targetRows = cur.fetchall()

    # Close the connection with the database.
    cur.close()

    return targetRows


# Define a function to fetch data from the database with value.
def FetchFromTheDatabseWithValue(executeString, values):

    # Start connection with the database.
    cur = mysql.connection.cursor()

    # Fetch from the database.
    cur.execute(executeString, values)
    targetRows = cur.fetchall()

    # Close the connection with the database.
    cur.close()

    return targetRows


# Define a function to put changes in the database.
def PutChangesInDatabase(executeString, values):
    
    # Start connection with the database.
    cur = mysql.connection.cursor()

    # Put changes in the database and commit it.
    cur.execute(executeString, values)
    mysql.connection.commit()

    # Close the connection with the database.
    cur.close()

MAIN_COMPANY = "passion"
MIN_GRADE = 19
SUPER_ADMIN_ID = 21 if 'DB_USER' in os.environ else 1

# Register page.
@app.route('/register', methods=['GET', 'POST'])
@app.route('/<company>/register', methods=['GET', 'POST'])
def Register(company=MAIN_COMPANY):

    # See if the company is exists.
    companyUsername = SearchInTheDatabaseWithValue("SELECT user_name FROM companies WHERE user_name = %s", [company])
    
    if not companyUsername:
        return render_template("error_messages.html", message="There is no company named " + company)

    # In 'GET' request case.
    if request.method == 'GET':
        return render_template("register.html", company=company)

    # In 'POST' request case.
    if request.method == 'POST':

        # Get the registration data from the form.
        name = request.form['name']
        phone = str(request.form['phone'])
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm']

        # Check the correctness of the form fields.
        if len(name) < 1 or len(name) > 50:
            return render_template("register.html", error="Invalid name. Try again")

        if len(phone) < 8 or len(phone) > 16:
            return render_template("register.html", error="Invalid phone number. Try again")

        if len(email) > 50:
            return render_template("register.html", error="Invalid Email. Try again")

        if len(password) < 6:
            return render_template("register.html", error="The password is too short. Try again") 
        
        if len(password) > 50:
            return render_template("register.html", error="The password is too long. Try again") 

        if password != confirm:
            return render_template("register.html", error="Passwords didn't mach. Try again")

        # Check if the phone number is used.
        if SearchInTheDatabaseWithValue("SELECT * FROM users WHERE phone = %s AND company = %s", [phone, company]):
            return render_template("register.html", error="This phone number is allready used!")
        
        # Crypt the password befor put it it on the database.
        password = sha256_crypt.encrypt(str(password))

        # See if the company still has quota.
        quota = FetchFromTheDatabseWithValue("SELECT quota FROM companies WHERE user_name = %s", [company])[0]['quota']

        if not quota or quota < 1:
            return render_template("error_messages.html", message="Sorry, " + company + " can't add mor users. Try to contact with them.")

        # Subtract the user from his company quota.
        PutChangesInDatabase("Update companies SET quota = %s WHERE user_name = %s", (quota - 1, company))

        # Insert user data in the 'users' table.
        try:
            PutChangesInDatabase("INSERT INTO users(name, phone, email, password, company) VALUES(%s, %s, %s, %s, %s)",
            (name, phone, email, password, company))
        except Exception as e:
            print(e)
            
        if company != MAIN_COMPANY:
            return redirect('/' + company + '/login')
        return redirect(url_for("Login"))


# Admin register page.
@app.route('/admin_register', methods=['GET', 'POST'])
@app.route('/<company>/admin_register', methods=['GET', 'POST'])
def AdminRegister(company=MAIN_COMPANY):

    # See if the company is exists.
    companyUsername = SearchInTheDatabaseWithValue("SELECT user_name FROM companies WHERE user_name = %s", [company])
    if not companyUsername:
        return render_template("error_messages.html", message="There is no company named " + company)

    # In 'GET' request case.
    if request.method == 'GET':
        return render_template("admin_register.html", company=company)

    # In 'POST' request case.
    if request.method == 'POST':

        # Get the registration data from the form.
        name = request.form['name']
        phone = str(request.form['phone'])
        password = request.form['password']
        confirm = request.form['confirm']

        # Check the correctness of the form fields.
        if len(name) < 1 or len(name) > 50:
            return render_template("admin_register.html", error="Invalid name. Try again")

        if len(phone) < 8 or len(phone) > 16:
            return render_template("admin_register.html", error="Invalid phone number. Try again")

        if len(password) < 6:
            return render_template("admin_register.html", error="The password is too short. Try again") 
        
        if len(password) > 50:
            return render_template("admin_register.html", error="The password is too long. Try again") 

        if password != confirm:
            return render_template("admin_register.html", error="Passwords didn't mach. Try again")

        # Check if the phone number is used.
        if SearchInTheDatabaseWithValue("SELECT * FROM admins WHERE phone = %s AND company = %s", [phone, company]):
            return render_template("admin_register.html", error="This phone number is allready used!")
        
        # Crypt the password befor put it it on the database.
        password = sha256_crypt.encrypt(str(password))
        
        # Insert admin data in the 'admins' table.
        PutChangesInDatabase("INSERT INTO admins(name, phone, password, company) VALUES(%s, %s, %s, %s)", (name, phone, password, company))
        
        if company != MAIN_COMPANY:
            return redirect('/' + company + '/admin_login')

        return redirect(url_for("AdminLogin"))


# Login page.
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
@app.route('/<company>/login', methods=['GET', 'POST'])
def Login(company=MAIN_COMPANY):

    # In 'GET' request case.
    if request.method == 'GET':
        return render_template('login.html', company=company)

    # In 'POST' request case.
    if request.method == 'POST':

        # Clear the session.
        session.clear()

        phone = request.form['phone']
        password = request.form['password']

        # Start connection with the database.
        cur = mysql.connection.cursor()

        # Check if the user existe.
        user = cur.execute("SELECT * FROM users WHERE phone = %s AND company = %s", [phone, company])
        if not user:
            return render_template("login.html", error="Invalid login")

        # Select the user row.
        userRow = cur.fetchone()

        # Close the connection with the database.
        cur.close()

        # Verify the password.
        verified = sha256_crypt.verify(password, userRow['password'])
        if not verified:
            return render_template("login.html", error="Incorrect password. Try again")

        # Check if the user have access to the exam.
        if not userRow['access']:
            return render_template("login.html", error="You do not have access yet.")
        
        # Put user login variable in session.
        session['user_logged_in'] = True
        session['user_id'] = str(userRow['id'])
        session['user_company'] = company

        if userRow['p_b1']:
            PutChangesInDatabase("UPDATE users SET got_pre_a1 = 1, f_pre_a1 = 1, got_a1 = 1, f_a1 = 1, got_a2 = 1, f_a2 = 1, got_b1 = 1, f_b1 = 1 WHERE id = %s", [session['user_id']])
            return redirect(url_for("MovingForward"))
        if userRow['p_a2']:
            PutChangesInDatabase("UPDATE users SET got_pre_a1 = 1, f_pre_a1 = 1, got_a1 = 1, f_a1 = 1, got_a2 = 1, f_a2 = 1 WHERE id = %s", [session['user_id']])
            return redirect(url_for("MovingForward"))
        if userRow['p_a1']:
            PutChangesInDatabase("UPDATE users SET got_pre_a1 = 1, f_pre_a1 = 1, got_a1 = 1, f_a1 = 1 WHERE id = %s", [session['user_id']])
            return redirect(url_for("MovingForward"))
        if userRow['p_pre_a1']:
            PutChangesInDatabase("UPDATE users SET got_pre_a1 = 1, f_pre_a1 = 1 WHERE id = %s", [session['user_id']])
            return redirect(url_for("MovingForward"))
        
        return redirect(url_for("MovingForward"))


# Admin login page.
@app.route("/admin_login", methods=['GET', 'POST'])
@app.route("/<company>/admin_login", methods=['GET', 'POST'])
def AdminLogin(company=MAIN_COMPANY):

    # In 'GET' request case.
    if request.method == 'GET':
        return render_template("admin_login.html", company=company)

    # In 'POST' request case.
    if request.method == 'POST':

        # Clear the session.
        session.clear()

        phone = str(request.form['phone'])
        password = str(request.form['password'])
        
        # Start connection with the database.
        cur = mysql.connection.cursor()
        
        # Check if the user existe.
        admin = cur.execute("SELECT * FROM admins WHERE phone = %s AND company = %s", [phone, company])
        if not admin:
            return render_template("admin_login.html", error='Invalid login.')

        # Select the admin row.
        adminRow = cur.fetchone()

        # Close the connection with the database.
        cur.close()

        # Verify the password.
        verified = sha256_crypt.verify(password, adminRow['password'])
        if not verified:
            return render_template("admin_login.html", error='Invalid password.')

        # Check the validity of the admin.
        if not adminRow['admin']:
            return render_template("admin_login.html", error='You are not an admin yet.')

        session['admin_logged_in'] = True
        session['admin_name'] = adminRow['name']
        session['admin_company'] = company
        session['admin_id'] = adminRow['id']

        if adminRow['can_d']:
            session["admin_can_d"] = True

        return redirect(url_for('Dashboard'))


# Logout.
@app.route('/logout')
def Logout():

    # If he is an admin return to 'admin_login' page.
    if "admin_company" in session and session["admin_company"] == MAIN_COMPANY:
        session.clear()
        return redirect(url_for('AdminLogin'))

    elif "admin_company" in session:
        company = session['admin_company']
        session.clear()
        return redirect('/' + company + "/admin_login") 

    # Deny the access when logout.
    try:
        PutChangesInDatabase("""UPDATE users SET access = 0, 
        got_pre_a1 = 0, f_pre_a1 = 0, got_a1 = 0, f_a1 = 0, got_a2 = 0, f_a2 = 0, got_b1 = 0, f_b1 = 0, got_b2 = 0,
        p_pre_a1 = 0, p_a1 = 0, p_a2 = 0, p_b1 = 0 
        WHERE id = %s""", [session['user_id']])
    except Exception as e:
        print(e)

    # If he is a user return to 'login' page.        

    if "user_company" in session and session["user_company"] != MAIN_COMPANY:
        company = session["user_company"]
        session.clear()
        return redirect('/' + company + "/login")
    else:
        print(session)
        session.clear()
        return redirect(url_for("Login"))


# Check if admin logged in.
def IsAdmin(func):
    @wraps(func)
    def wrap(*args, **kwargs):
        if "admin_logged_in" in session:
            return func(*args, **kwargs)
        return redirect(url_for('AdminLogin'))
    return wrap


# Dashboard page.
@app.route('/dashboard')
@IsAdmin
def Dashboard(): 

    # Select all users from users table.
    users = list(FetchFromTheDatabseWithValue("SELECT * FROM users WHERE company = %s", [session['admin_company']]))

    # Reverse users order to show up in the dashboard from newest to oldest.
    users.reverse()

    return render_template('dashboard.html', users=users)


@app.route("/dashboard/<user_id>/set-access", methods=['POST'])
@IsAdmin
def SetAccess(user_id):
    accessValue = request.get_json()['access']

    PutChangesInDatabase("UPDATE users SET access = %s WHERE id = %s AND company = %s", (accessValue, user_id, session['admin_company']))

    return redirect(url_for("Dashboard"))


@app.route("/dashboard/search", methods=['GET', 'POST'])
@IsAdmin
def DashboardSearch():
    searchValue = request.args.get("search") if request.method == 'GET' else request.form['search']
    
    results = list(FetchFromTheDatabse("""SELECT * FROM users WHERE (phone LIKE '%%%s%%' AND company = '%s') OR 
                                        (name LIKE '%%%s%%' AND company = '%s')""" % 
    (searchValue, session['admin_company'], searchValue, session['admin_company'])))

    results.reverse()

    if request.method == 'POST':
        return jsonify(results)

    return render_template("dashboard.html", users=results)


# Check if user logged in.
def IsUserLoggedin(func):
    @wraps(func)
    def wrap(*args, **kwargs):
        if "user_logged_in" in session:
            return func(*args, **kwargs)
        return redirect(url_for('Logout'))
    return wrap


# Define a function to mark the regular test parts (four-questions).
def MarkingTheOneQuestionTestPart(rightAnswers, part):
    partMarks = 0
    for partNum in range(len(rightAnswers)):
        if request.form.get(part + str(partNum+1)) == rightAnswers[partNum]:
            partMarks += 1

    return partMarks


# Define a function to mark the one-questions test parts.
def MarkingTheFourQuestionsTestPart(rightAnswers, part):
    partMarks = 0
    userPartAnswers = request.form.getlist(part)

    for i in range(len(userPartAnswers)):
        if userPartAnswers[i] in rightAnswers:
            partMarks += 1

    return partMarks


# Test 'Pre A1' page.
@app.route("/test_pre_A1", methods=['GET', 'POST'])
@IsUserLoggedin
def TestPreA1():

    # In 'GET' request case.
    if request.method == 'GET':
        
        # Check if user got into 'pre_A1' test before.
        if FetchFromTheDatabseWithValue("SELECT got_pre_a1 FROM users WHERE id = %s", [session['user_id']])[0]['got_pre_a1']:
            return redirect(url_for("Logout"))
        PutChangesInDatabase("UPDATE users SET got_pre_a1 = 1 WHERE id = %s", [session['user_id']])
        
        return render_template("test_pre_A1.html")

    # In 'POST' request case.
    if request.method == 'POST':

        # Set in the database that: the user has finished the 'pre_A1" test.
        PutChangesInDatabase("UPDATE users SET f_pre_a1 = 1 WHERE id = %s", [session['user_id']])

        # The correct answers.
        p1Answers = ['A', 'C', 'E', 'G']
        p2Answers = ['B', 'C', 'A', 'B']
        p3Answers = ['A', 'A', 'C', 'A']
        p4Answers = ['B', 'A', 'B', 'C']
        p5Answers = ['B', 'A', 'A', 'C', 'B', 'C', 'A', 'C']

        # Initialize variables to represent the test marks.
        totalMarks = 0
        listeningMarks = 0
        readingMarks = 0
        grammarMarks = 0
        functionalMarks = 0
        grammar2Marks = 0
        
        # Get user marks the 'listening' part.
        listeningMarks = MarkingTheFourQuestionsTestPart(p1Answers, "listening")
        totalMarks += listeningMarks

        # Get user marks the 'reading' part.
        readingMarks = MarkingTheOneQuestionTestPart(p2Answers, "reading")
        totalMarks += readingMarks

        # Get user marks the 'grammar' part.
        grammarMarks = MarkingTheOneQuestionTestPart(p3Answers, "grammar")
        totalMarks += grammarMarks

        # Get user marks the 'functional' part.
        functionalMarks = MarkingTheOneQuestionTestPart(p4Answers, "functional_language")
        totalMarks += functionalMarks

        # Get user marks the 'grammar2' part.
        grammar2Marks = MarkingTheOneQuestionTestPart(p5Answers, "2grammar")
        totalMarks += grammar2Marks

        # Get the test numder for the user.
        testNumber = SearchInTheDatabaseWithValue("SELECT * FROM tests WHERE id = %s", [session['user_id']]) + 1
        
        # Insert the 'pre a1' test marks in the 'tests' table.
        PutChangesInDatabase("INSERT INTO tests(id, test_num, lpre_a1, rpre_a1, gpre_a1, fpre_a1, g2pre_a1, pre_a1) VALUES(%s, %s, %s, %s, %s, %s, %s, %s)",
        (session['user_id'], testNumber, listeningMarks, readingMarks, grammarMarks, functionalMarks, grammar2Marks, totalMarks))


        # If the user passed the test, redirect him to the next exam.
        if totalMarks >= MIN_GRADE:
            return redirect(url_for("MovingForward"))
        
        # If the user didn't pass the test, redirect him to the 'UserResults' page.
        return redirect(url_for("UserResults"))


# Test 'A1' page.
@app.route("/test_A1", methods=['GET', 'POST'])
@IsUserLoggedin
def TestA1():

    # In 'GET' request case.
    if request.method == 'GET':
        
        # Check if the user can take the test.
        userRow = FetchFromTheDatabseWithValue("SELECT * FROM users WHERE id = %s", [session['user_id']])[0]
        if not userRow['got_pre_a1'] or not userRow['f_pre_a1'] or userRow['got_a1']:
            return redirect(url_for("Logout"))

        PutChangesInDatabase("UPDATE users SET got_a1 = 1 WHERE id = %s", [session['user_id']])
        
        return render_template("test_A1.html")

    # In 'POST' request case.
    if request.method == 'POST':

        # Set in the database that: the user has finished the 'A1" test.
        PutChangesInDatabase("UPDATE users SET f_a1 = 1 WHERE id = %s", [session['user_id']])

        # The correct answers.
        p1Answers = ['A', 'D', 'B', 'B']
        p2Answers = ['D', 'D', 'D', 'C']
        p3Answers = ['D', 'B', 'C', 'C']
        p4Answers = ['A', 'C', 'C', 'A']
        p5Answers = ['B', 'D', 'A', 'C', 'D', 'B', 'A', 'C']

        # Initialize variables to represent the test marks.
        totalMarks = 0
        listeningMarks = 0
        readingMarks = 0
        vocabularyMarks = 0
        functionalMarks = 0
        grammarMarks = 0

        # Get user marks the 'listening' part.
        listeningMarks = MarkingTheOneQuestionTestPart(p1Answers, "listening")
        totalMarks += listeningMarks

        # Get user marks the 'reading' part.
        readingMarks = MarkingTheOneQuestionTestPart(p2Answers, "reading")
        totalMarks += readingMarks

        # Get user marks the 'vocabulary' part.
        vocabularyMarks = MarkingTheOneQuestionTestPart(p3Answers, "vocabulary")
        totalMarks += vocabularyMarks

        # Get user marks the 'functional' part.
        functionalMarks = MarkingTheOneQuestionTestPart(p4Answers, "functional_language")
        totalMarks += functionalMarks

        # Get user marks the 'grammar' part.
        grammarMarks = MarkingTheOneQuestionTestPart(p5Answers, "grammar")
        totalMarks += grammarMarks

        # Get the test numder for the user.
        testNumber = SearchInTheDatabaseWithValue("SELECT * FROM tests WHERE id = %s", [session['user_id']])
        
        # Update the 'A1' test marks in the 'tests' table.
        PutChangesInDatabase("UPDATE tests SET la1 = %s, ra1 = %s, va1 = %s, fa1 = %s, ga1 = %s, a1 = %s WHERE id = %s and test_num = %s",
        (listeningMarks, readingMarks, vocabularyMarks, functionalMarks, grammarMarks, totalMarks, session['user_id'], testNumber))

        # If the user passed the test, redirect him to the next exam.
        if totalMarks >= MIN_GRADE:
            return redirect(url_for("MovingForward"))
        
        # If the user didn't pass the test, redirect him to the 'UserResults' page.
        return redirect(url_for("UserResults"))


# Test 'A2' page.
@app.route("/test_A2", methods=['GET', 'POST'])
@IsUserLoggedin
def TestA2():

    # In 'GET' request case.
    if request.method == 'GET':
        
        # Check if the user can take the test.
        userRow = FetchFromTheDatabseWithValue("SELECT * FROM users WHERE id = %s", [session['user_id']])[0]
        if not userRow['got_a1'] or not userRow['f_a1'] or userRow['got_a2']:
            return redirect(url_for("Logout"))

        PutChangesInDatabase("UPDATE users SET got_a2 = 1 WHERE id = %s", [session['user_id']])
        
        return render_template("test_A2.html")

    # In 'POST' request case.
    if request.method == 'POST':

        # Set in the database that: the user has finished the 'A1" test.
        PutChangesInDatabase("UPDATE users SET f_a2 = 1 WHERE id = %s", [session['user_id']])
        
        # The correct answers.
        p1Answers = ['B', 'D', 'G', 'J']
        p2Answers = ['D', 'C', 'B', 'D']
        p3Answers = ['A', 'C', 'A', 'C']
        p4Answers = ['A', 'D', 'B', 'C']
        p5Answers = ['A', 'D', 'B', 'C', 'A', 'A', 'A', 'A']

        # Initialize variables to represent the test marks.
        totalMarks = 0
        listeningMarks = 0
        readingMarks = 0
        vocabularyMarks = 0
        functionalMarks = 0
        grammarMarks = 0

        # Get user marks the 'listening' part.
        listeningMarks = MarkingTheFourQuestionsTestPart(p1Answers, "listening")
        totalMarks += listeningMarks

        # Get user marks the 'reading' part.
        readingMarks = MarkingTheOneQuestionTestPart(p2Answers, "reading")
        totalMarks += readingMarks

        # Get user marks the 'vocabulary' part.
        vocabularyMarks = MarkingTheOneQuestionTestPart(p3Answers, "vocabulary")
        totalMarks += vocabularyMarks

        # Get user marks the 'functional' part.
        functionalMarks = MarkingTheOneQuestionTestPart(p4Answers, "functional_language")
        totalMarks += functionalMarks

        # Get user marks the 'grammar' part.
        grammarMarks = MarkingTheOneQuestionTestPart(p5Answers, "grammar")
        totalMarks += grammarMarks

        # Get the test numder for the user.
        testNumber = SearchInTheDatabaseWithValue("SELECT * FROM tests WHERE id = %s", [session['user_id']])
        
        # Update the 'A1' test marks in the 'tests' table.
        PutChangesInDatabase("UPDATE tests SET la2 = %s, ra2 = %s, va2 = %s, fa2 = %s, ga2 = %s, a2 = %s WHERE id = %s and test_num = %s",
        (listeningMarks, readingMarks, vocabularyMarks, functionalMarks, grammarMarks, totalMarks, session['user_id'], testNumber))

        # If the user passed the test, redirect him to the next exam.
        if totalMarks >= MIN_GRADE:
            return redirect(url_for("MovingForward"))
        
        # If the user didn't pass the test, redirect him to the 'UserResults' page.
        return redirect(url_for("UserResults"))
        

# Test 'B1' page.
@app.route("/test_B1", methods=['GET', 'POST'])
@IsUserLoggedin
def TestB1():

    # In 'GET' request case.
    if request.method == 'GET':
        
        # Check if the user can take the test.
        userRow = FetchFromTheDatabseWithValue("SELECT * FROM users WHERE id = %s", [session['user_id']])[0]
        if not userRow['got_a2'] or not userRow['f_a2'] or userRow['got_b1']:
            return redirect(url_for("Logout"))

        PutChangesInDatabase("UPDATE users SET got_b1 = 1 WHERE id = %s", [session['user_id']])
        
        return render_template("test_B1.html")

    # In 'POST' request case.
    if request.method == 'POST':

        # Set in the database that: the user has finished the 'A1" test.
        PutChangesInDatabase("UPDATE users SET f_b1 = 1 WHERE id = %s", [session['user_id']])
        
        # The correct answers.
        p1Answers = ['A', 'C', 'D', 'G']
        p2Answers = ['A', 'B', 'C', 'B']
        p3Answers = ['C', 'B', 'A', 'B']
        p4Answers = ['C', 'C', 'B', 'A']
        p5Answers = ['A', 'B', 'B', 'B', 'B', 'B', 'A', 'A']

        # Initialize variables to represent the test marks.
        totalMarks = 0
        listeningMarks = 0
        readingMarks = 0
        phoneticsMarks = 0
        functionalMarks = 0
        grammarMarks = 0

        # Get user marks the 'listening' part.
        listeningMarks = MarkingTheFourQuestionsTestPart(p1Answers, "listening")
        totalMarks += listeningMarks

        # Get user marks the 'reading' part.
        readingMarks = MarkingTheOneQuestionTestPart(p2Answers, "reading")
        totalMarks += readingMarks

        # Get user marks the 'phonetics' part.
        phoneticsMarks = MarkingTheOneQuestionTestPart(p3Answers, "phonetics")
        totalMarks += phoneticsMarks

        # Get user marks the 'functional' part.
        functionalMarks = MarkingTheOneQuestionTestPart(p4Answers, "functional_language")
        totalMarks += functionalMarks

        # Get user marks the 'grammar' part.
        grammarMarks = MarkingTheOneQuestionTestPart(p5Answers, "grammar")
        totalMarks += grammarMarks

        # Get the test numder for the user.
        testNumber = SearchInTheDatabaseWithValue("SELECT * FROM tests WHERE id = %s", [session['user_id']])
        
        # Update the 'A1' test marks in the 'tests' table.
        PutChangesInDatabase("UPDATE tests SET lb1 = %s, rb1 = %s, phb1 = %s, fb1 = %s, gb1 = %s, b1 = %s WHERE id = %s and test_num = %s",
        (listeningMarks, readingMarks, phoneticsMarks, functionalMarks, grammarMarks, totalMarks, session['user_id'], testNumber))

        # If the user passed the test, redirect him to the next exam.
        if totalMarks >= MIN_GRADE:
            return redirect(url_for("MovingForward"))
        
        # If the user didn't pass the test, redirect him to the 'UserResults' page.
        return redirect(url_for("UserResults"))


# Test 'B2' page.
@app.route("/test_B2", methods=['GET', 'POST'])
@IsUserLoggedin
def TestB2():

    # In 'GET' request case.
    if request.method == 'GET':
        
        # Check if the user can take the test.
        userRow = FetchFromTheDatabseWithValue("SELECT * FROM users WHERE id = %s", [session['user_id']])[0]
        if not userRow['got_b1'] or not userRow['f_b1'] or userRow['got_b2']:
            return redirect(url_for("Logout"))

        PutChangesInDatabase("UPDATE users SET got_b2 = 1 WHERE id = %s", [session['user_id']])
        
        return render_template("test_B2.html")

    # In 'POST' request case.
    if request.method == 'POST':

        p1Answers = ['A', 'C', 'G', 'H']
        p2Answers = ['A', 'C', 'E', 'F']
        p3Answers = ['A', 'B', 'C', 'A']
        p4Answers = ['B', 'A', 'A', 'A']
        p5Answers = ['A', 'A', 'B', 'A', 'A', 'A', 'B', 'A']

        # Initialize variables to represent the test marks.
        totalMarks = 0
        listeningMarks = 0
        readingMarks = 0
        vocabularyMarks = 0
        functionalMarks = 0
        grammarMarks = 0

        # Get user marks the 'listening' part.
        listeningMarks = MarkingTheFourQuestionsTestPart(p1Answers, "listening")
        totalMarks += listeningMarks

        # Get user marks the 'reading' part.
        readingMarks = MarkingTheFourQuestionsTestPart(p2Answers, "reading")
        totalMarks += readingMarks

        # Get user marks the 'phonetics' part.
        vocabularyMarks = MarkingTheOneQuestionTestPart(p3Answers, "vocabulary")
        totalMarks += vocabularyMarks

        # Get user marks the 'functional' part.
        functionalMarks = MarkingTheOneQuestionTestPart(p4Answers, "functional_language")
        totalMarks += functionalMarks

        # Get user marks the 'grammar' part.
        grammarMarks = MarkingTheOneQuestionTestPart(p5Answers, "grammar")
        totalMarks += grammarMarks

        # Get the test numder for the user.
        testNumber = SearchInTheDatabaseWithValue("SELECT * FROM tests WHERE id = %s", [session['user_id']])
        
        # Update the 'A1' test marks in the 'tests' table.
        PutChangesInDatabase("UPDATE tests SET lb2 = %s, rb2 = %s, vb2 = %s, fb2 = %s, gb2 = %s, b2 = %s WHERE id = %s and test_num = %s",
        (listeningMarks, readingMarks, vocabularyMarks, functionalMarks, grammarMarks, totalMarks, session['user_id'], testNumber))

        return redirect(url_for("UserResults"))


# Tests results page for user.
@app.route("/user_results")
@IsUserLoggedin
def UserResults():

    # Get user tests.
    userTests = list(FetchFromTheDatabseWithValue("SELECT * FROM tests WHERE id = %s", [session['user_id']]))
    userTests.reverse()

    # Get user data
    userRow = FetchFromTheDatabseWithValue("SELECT name, phone, email, date FROM users WHERE id = %s", [session['user_id']])[0]

    Logout()

    return render_template('test_results.html', tests=userTests, userRow=userRow)
     
    
# Tests results page for admins.
@app.route('/tests_results/<string:id>')
@IsAdmin
def TestsResults(id):

    # Get user tests.
    userTests = list(FetchFromTheDatabseWithValue("SELECT * FROM tests WHERE id = %s", [id]))
    userTests.reverse()

    userRow = FetchFromTheDatabseWithValue("SELECT * FROM users WHERE id = %s", [id])[0]
    
    # Check the accessability for admin
    if userRow['company'] != session["admin_company"]:
        return render_template("error_messages.html", message="You are not allowed to view this user!")
    
    return render_template('test_results.html', tests=userTests, userRow=userRow)

# Delete user.
@app.route('/delete/<string:id>/')
@IsAdmin
def Delete(id):

    # Check if the admin is allowed to delete users.
    if "admin_can_d" in session:

        # Check the accessability for admin.
        userCompany = FetchFromTheDatabseWithValue("SELECT company FROM users WHERE id = %s", [id])[0]

        if userCompany['company'] != session["admin_company"]:
            return render_template("error_messages.html", message="You are not allowed to delete this user!")

        # Delete the user row from 'users' table in the database.
        PutChangesInDatabase("DELETE FROM users WHERE id = %s AND company = %s", [id, session['admin_company']])

        # Delete users tests from 'tests' table.
        for testNum in range(SearchInTheDatabaseWithValue("SELECT * FROM tests WHERE id = %s", [id])):
            PutChangesInDatabase("DELETE FROM tests WHERE id = %s and test_num = %s", (id, testNum+1))

    
    return redirect(url_for('Dashboard'))

@app.route("/moving_forward", methods=['GET', 'POST'])
@IsUserLoggedin
def MovingForward():

    # In 'GET' request case.
    if request.method == 'GET':

        tests = ["B1", "A2", "A1", "Pre_A1"]
        for finshedTest, pastTestName in zip(["f_b1", "f_a2", "f_a1", "f_pre_a1"], tests):
            if SearchInTheDatabase("SELECT * FROM users WHERE (id = {0}) and {1} = 1".format(session['user_id'], finshedTest)):
                testsNum = SearchInTheDatabase("SELECT * FROM tests WHERE (id = {0})".format(session['user_id']))
                lastExamGrades = FetchFromTheDatabse("SELECT * FROM tests WHERE (id = {0}) and (test_num = {1})".format(session['user_id'], testsNum))[0][pastTestName.lower()]
                return render_template("moving_forward.html", text="Go to the next stage (" + tests[tests.index(pastTestName) - 1] + ")" if pastTestName != "B1" else "Go to the next stage (B2)", pastTestName=pastTestName, grades=lastExamGrades)

        return render_template("moving_forward.html", start="Start", text="Would you like to start Pre A1?")
    
    # In 'GET' request case.
    if request.method == 'POST':

        for finshedTest, testFunc in zip(["f_b1", "f_a2", "f_a1", "f_pre_a1"], ["TestB2", "TestB1", "TestA2", "TestA1"]):
            if SearchInTheDatabaseWithValue("SELECT * FROM users WHERE id = %s and " + finshedTest + " = 1", [session['user_id']]):
                return redirect(url_for(testFunc))

        return redirect(url_for("TestPreA1"))


# Reset password page.
@app.route('/reset_password/<string:id>/', methods=['GET', 'POST'])
@IsAdmin
def RestPassword(id):

    # Check the accessability for admin.
    userCompany = FetchFromTheDatabseWithValue("SELECT company FROM users WHERE id = %s", [id])[0]

    if userCompany['company'] != session["admin_company"]:
        return render_template("error_messages.html", message="You are not allowed for this action")

    # In 'GET' request case.
    if request.method == 'GET':
        return render_template('reset_password.html')

    # In 'POST' request case.
    if request.method == 'POST':

        # Get the new password.
        password = request.form['password']
        confirm = request.form['confirm']

        # Check the validation of the password.
        passwordLen = len(password)

        if passwordLen > 50:
            return render_template('reset_password.html', error = "Password is too long")
        if passwordLen < 6:
            return render_template('reset_password.html', error = "Password is too short")
        if password != confirm:
            return render_template('reset_password.html', error = "Passwords didn't mach. Try again")

        # Crypt the password before put it in the database. 
        password = sha256_crypt.encrypt(str(password))

        # Updata user password.
        PutChangesInDatabase("UPDATE users SET password = %s WHERE id = %s", (password, id))

        
        return redirect(url_for('Dashboard'))


# Define a function to make the user pass a certain test.
@app.route('/pass_test/<string:id>/<string:test>')
@IsAdmin
def PassTest(id, test):

    if test not in ['p_pre_a1', 'p_a1', 'p_a2', 'p_b1']:
        return "Something went wrong!"

    # Get the value of the certain test.
    passValue = 1
    if SearchInTheDatabaseWithValue("SELECT * FROM users WHERE id = %s AND " + test + " = 1", [id]):
        passValue = 0

    # Change the pass test value of that user.
    PutChangesInDatabase("UPDATE users SET " + test + " = %s WHERE id = %s AND company = %s", [passValue, id, session["admin_company"]])

    return redirect('/tests_results/{0}'.format(id))


@app.route("/download_users")
@IsAdmin
def DownloadUsers():
    
    # Get all users data.
    users = FetchFromTheDatabseWithValue("SELECT id, name, phone, email, date FROM users WHERE company = %s", [session["admin_company"]])

    # Get the last test for each user.
    usersTests = []
    for user in users:
        usersTests.append(FetchFromTheDatabse("SELECT * FROM tests WHERE test_num = (SELECT COUNT(*) FROM tests WHERE id = {0}) AND id = {1}".format(user['id'], user['id'])))

    # Wite the data in the 'users,csv' file.
    with open("users.csv", 'w', newline='') as csvFile:
        writer = csv.writer(csvFile)

        # Write the file head.
        writer.writerow([
            'ID', 'Name', 'Phone', 'Email', 'Registration date', "Exam date", 
            'Listening_Pre_A1(4)', 'Reading_Pre_A1(4)', 'Grammar_Pre_A1(4)', 'Functional_language_Pre_A1(4)', 'Grammar_Pre_A1(8)', 'Pre_A1(24)',
            'listening_A1(4)', 'Reading_A1(4)', 'Vocabulary_A1(4)', 'Functional_language_A1(4)', 'Grammar_A1(8)', 'A1(24)', 
            'listening_A2(4)', 'Reading_A2(4)', 'Vocabulary_A2(4)', 'Functional_language_A2(4)', 'Grammar_A2(8)', 'A2(24)', 
            'listening_B1(4)', 'Reading_B1(4)', 'phonetics_B1(4)', 'Functional_language_B1(4)', 'Grammar_B1(8)', 'B1(24)', 
            'listening_B2(4)', 'Reading_B2(4)', 'Vocabulary_B2(4)', 'Functional_language_B2(4)', 'Grammar_B2(8)', 'B2(24)', 
            ])
        
        # Write users data.
        for user, userTest in zip(users, usersTests):
            writer.writerow(list(user.values()) + (list(userTest[0].values())[2:] if userTest else []))

    return send_file('users.csv',
    mimetype='text/csv',
    cache_timeout=0,
    attachment_filename='users.csv',
    as_attachment=True)


# Edit the time to add 2 hours to the GMT.
def datetimefilter(value, format="%Y-%m-%d %H:%M:%S"):
    value = value + timedelta(weeks=0, days=0, hours=2, minutes=0, seconds=0)
    return value.strftime(format)

app.jinja_env.filters['datetimefilter'] = datetimefilter


# Company Register page.
@app.route("/company_register", methods=['GET', 'POST'])
def CompanyRegister():

    if request.method == 'GET':
        return render_template("company_register.html")
    
    # In 'POST' request case.
    else:

        # Get the registration data from the form.
        userName = request.form['userName']
        businessName = request.form['businessName']
        email = request.form['email']
        phone = request.form['phone']
        website = request.form['website']
        facebook = request.form['facebook']
        twitter = request.form['twitter']
        country = request.form['country']
        city = request.form['city']
        zip = request.form['zip']
        logo = request.files['logo']
        businessAdress = request.form['businessAdress']
        about = request.form['about']
        commercialRegistrationNumber = request.form['commercialRegistrationNumber']
        commercialRegistryFile = request.files['commercialRegistryFile']
        personalIDNumber = request.form['personalIDNumber']
        personalIDImage = request.files['personalIDImage']
        taxID = request.form['taxID']
        taxIDFile = request.files['taxIDFile']

        # Check the validation of fields.
        if len(userName) < 3:
            return render_template("company_register.html", error="User name is too short. Try again")
        if len(userName) > 30:
            return render_template("company_register.html", error="User name is too long. Try again")
        if '/' in userName or '\\' in userName:
            return render_template("company_register.html", error="User name can't have '/' or '\\'. Try again")

        if len(businessName) > 30:
            return render_template("company_register.html", error="Business name is too long. Try again")

        if len(email) < 3:
            return render_template("company_register.html", error="Email is too short. Try again")
        if len(email) > 50:
            return render_template("company_register.html", error="Email is too long. Try again")

        if len(phone) < 8 or len(phone) > 16:
            return render_template("company_register.html", error="Invalid phone number. Try again")

        if len(country) > 60:
            return render_template("company_register.html", error="Something went wrong. Try again")

        if len(city) > 85:
            return render_template("company_register.html", error="City name is too long. Try again")

        if len(zip) > 10:
            return render_template("company_register.html", error="ZIP code is too long. Try again")

        if len(commercialRegistrationNumber) > 10:
            return render_template("company_register.html", error="Commercial registration number is too long. Try again")

        if len(personalIDNumber) > 20:
            return render_template("company_register.html", error="Personal ID number is too long. Try again")
       
        if len(taxID) > 10:
            return render_template("company_register.html", error="Tax ID is too long. Try again")

        # Search 'user name' in the database.
        if SearchInTheDatabaseWithValue("SELECT user_name FROM companies WHERE user_name = %s", [userName]):
            return render_template("company_register.html", error="This user name is already used!")
      
        # Insert fields values in the database (companies table).
        try:
            PutChangesInDatabase("""INSERT INTO companies (user_name, business_name,
                                    email, phone, website, facebook, twitter,
                                    country, city, zip, logo, logo_name, business_address,
                                    about, commercial_registration_number, 
                                    commercial_registry_file, commercial_registry_file_name, personal_id_number,
                                    personal_id_image, personal_id_image_name, tax_id, tax_id_file, tax_id_file_name) 
                                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)""",
            (userName, businessName, email, phone, website, facebook, twitter, country, city, zip, 
                logo.read(), logo.filename, businessAdress, about, commercialRegistrationNumber,
                commercialRegistryFile.read(), commercialRegistryFile.filename,
                personalIDNumber, personalIDImage.read(), personalIDImage.filename, taxID, taxIDFile.read(), taxIDFile.filename))
        except Exception as e:
            print(e)
            return render_template("company_register.html", error="Something went wrong.")

        return render_template("company_register.html", success="Your data has been saved!")


@app.route("/companies_dashboard")
@IsAdmin
def CompaniesDashboard():

    # Check if he is the super admin.
    if FetchFromTheDatabseWithValue("SELECT id FROM admins WHERE id = %s", [SUPER_ADMIN_ID])[0]['id'] != session["admin_id"]:
        return render_template("error_messages.html", message="You are not allawed for this action!")


    # Fetch all data needed from database.
    companiesData = FetchFromTheDatabse("SELECT id, user_name, quota FROM companies")
    admins = FetchFromTheDatabse("SELECT * FROM admins")

    return render_template('company_dashboard.html', companiesData=companiesData, admins=admins)


@app.route("/<tapleField>/<adminID>", methods=['POST'])
@IsAdmin
def SetAdminValidations(tapleField, adminID):

    # Check if he is the super admin.
    if FetchFromTheDatabseWithValue("SELECT id FROM admins WHERE id = %s", [SUPER_ADMIN_ID])[0]['id'] != session["admin_id"]:
        return render_template("error_messages.html", message="You are not allawed for this action!")

    if tapleField not in ['admin', 'can_d']:
        return render_template("error_messages.html", message="Something went wrong!")

    # Get checkbox value.
    checked = request.get_json()['checked']
    
    PutChangesInDatabase("UPDATE admins SET " + tapleField + " = %s WHERE id = %s", (checked, adminID))

    return redirect(url_for("CompaniesDashboard"))


@app.route("/adding_quota", methods=['GET', 'POST'])
@IsAdmin
def AddQouta():

    # Check if he is the super admin.
    if FetchFromTheDatabseWithValue("SELECT id FROM admins WHERE id = %s", [SUPER_ADMIN_ID])[0]['id'] != session["admin_id"]:
        return render_template("error_messages.html", message="You are not allawed for this action!")
    
    # Get the request variables.
    addedQuota = request.form.get("quota")
    company = request.form.get("company")

    addedQuota = int(addedQuota) if addedQuota else 0

    # Saveing the added quota informations (in "company_quota" table).
    PutChangesInDatabase("INSERT INTO company_quota (company, quota) VALUES (%s, %s)", (company, addedQuota))

    # Update the quota (in "companies" table).
    companyActualQuota = FetchFromTheDatabseWithValue("SELECT quota FROM companies WHERE user_name = %s", [company])[0]['quota']

    finalQuota = companyActualQuota + addedQuota if companyActualQuota else addedQuota
    print(type(companyActualQuota), type(addedQuota), 'kkkkkkkkkkkkkk', company)
    PutChangesInDatabase("UPDATE companies SET quota = %s WHERE user_name = %s", (finalQuota, company))
    
    return redirect(url_for("CompaniesDashboard"))


@app.route("/company_info/<companyId>")
@IsAdmin
def CompanyInfo(companyId):

    # Check if he is the super admin.
    if FetchFromTheDatabseWithValue("SELECT id FROM admins WHERE id = %s", [SUPER_ADMIN_ID])[0]['id'] != session["admin_id"]:
        return render_template("error_messages.html", message="You are not allawed for this action!")

    companyData = FetchFromTheDatabseWithValue("SELECT * FROM companies WHERE id = %s", [companyId])[0]

    return render_template("company_info.html", company=companyData)


@app.route("/download_company_file/<companyId>/<field>")
@IsAdmin
def download(companyId, field):

    # Check if he is the super admin.
    if FetchFromTheDatabseWithValue("SELECT id FROM admins WHERE id = %s", [SUPER_ADMIN_ID])[0]['id'] != session["admin_id"]:
        return render_template("error_messages.html", message="You are not allawed for this action!")

    if field not in ['logo', 'commercial_registry_file', 'personal_id_image', 'tax_id_file']:
        return render_template("error_messages.html", message="Somthing went wrong!")

    targestFile = FetchFromTheDatabseWithValue("SELECT " + field + ", " + field + "_name FROM companies WHERE id = %s", [companyId])[0]

    return send_file(BytesIO(targestFile[field]), attachment_filename=targestFile[field + "_name"], as_attachment=True, cache_timeout=0)

 
if __name__ == '__main__':
    
    if 'DB_USER' in os.environ:
        app.run()
    else:
        app.run(debug=True)