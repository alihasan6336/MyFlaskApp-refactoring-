from flask import Flask, render_template, url_for, redirect, session, request
from flask_mysqldb import MySQL
from wtforms import Form
from passlib.hash import sha256_crypt
from functools import wraps
import datetime
import csv
from flask import send_file
import os


app = Flask(__name__)

app.config['SESSION_TYPE'] = 'filesystem'

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
    app.config["MYSQL_PASSWORD"] = "M01019056637m"
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
    selectionResults = cur.execute(executeString, [value])

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
    cur.execute(executeString, [values])
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


# Register page.
@app.route('/register', methods=['GET', 'POST'])
def Register():

    # In 'GET' request case.
    if request.method == 'GET':
        return render_template("register.html")

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

        if len(password) < 3:
            return render_template("register.html", error="The password is too short. Try again") 
        
        if len(password) > 50:
            return render_template("register.html", error="The password is too long. Try again") 

        if password != confirm:
            return render_template("register.html", error="Passwords didn't mach. Try again")

        # Check if the phone number is used.
        if SearchInTheDatabase("SELECT * FROM users WHERE phone = " + phone):
            return render_template("register.html", error="This phone number is allready used!")
        
        # Crypt the password befor put it it on the database.
        password = sha256_crypt.encrypt(str(password))
        
        # Insert user data in the 'users' table.
        PutChangesInDatabase("INSERT INTO users(name, phone, email, password) VALUES(%s, %s, %s, %s)",
        (name, phone, email, password))

        return redirect(url_for("Login"))


# Admin register page.
@app.route('/admin_register', methods=['GET', 'POST'])
def AdminRegister():

    # In 'GET' request case.
    if request.method == 'GET':
        return render_template("admin_register.html")

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

        if len(password) < 3:
            return render_template("admin_register.html", error="The password is too short. Try again") 
        
        if len(password) > 50:
            return render_template("admin_register.html", error="The password is too long. Try again") 

        if password != confirm:
            return render_template("admin_register.html", error="Passwords didn't mach. Try again")

        # Check if the phone number is used.
        if SearchInTheDatabase("SELECT * FROM admins WHERE phone = " + phone):
            return render_template("admin_register.html", error="This phone number is allready used!")
        
        # Crypt the password befor put it it on the database.
        password = sha256_crypt.encrypt(str(password))
        
        # Insert admin data in the 'admins' table.
        PutChangesInDatabase("INSERT INTO admins(name, phone, password) VALUES(%s, %s, %s)", (name, phone, password))
        
        return redirect(url_for("AdminLogin"))


# Login page.
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def Login():

    # In 'GET' request case.
    if request.method == 'GET':
        return render_template('login.html')

    # In 'POST' request case.
    if request.method == 'POST':

        # Clear the session.
        session.clear()

        phone = request.form['phone']
        password = request.form['password']

        # Start connection with the database.
        cur = mysql.connection.cursor()

        # Check if the user existe.
        user = cur.execute("SELECT * FROM users WHERE phone = %s", [phone])
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
def AdminLogin():

    # In 'GET' request case.
    if request.method == 'GET':
        return render_template("admin_login.html")

    # In 'POST' request case.
    if request.method == 'POST':

        # Clear the session.
        session.clear()

        phone = str(request.form['phone'])
        password = str(request.form['password'])
        
        # Start connection with the database.
        cur = mysql.connection.cursor()
        
        # Check if the user existe.
        admin = cur.execute("SELECT * FROM admins WHERE phone = %s", [phone])
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
            return render_template("admin_login.html", error='You are not admin yet.')

        session['admin_logged_in'] = True
        session['admin_name'] = adminRow['name']
        if adminRow['can_d']:
            session["admin_can_d"] = True

        return redirect(url_for('Dashboard'))


# Logout.
@app.route('/logout')
def Logout():

    # If he is an admin return to 'admin_login' page.
    if "admin_logged_in" in session:
        session.clear()
        return redirect(url_for('AdminLogin'))

    # Deny the access when logout.
    try:
        PutChangesInDatabase("""UPDATE users SET access = 0, 
        got_pre_a1 = 0, f_pre_a1 = 0, got_a1 = 0, f_a1 = 0, got_a2 = 0, f_a2 = 0, got_b1 = 0, f_b1 = 0, got_b2 = 0,
        p_pre_a1 = 0, p_a1 = 0, p_a2 = 0, p_b1 = 0 
        WHERE id = %s""", [session['user_id']])
    except Exception:
        pass

    # If he is a user return to 'login' page.
    session.clear()
    return redirect(url_for('Login'))


# Check if admin logged in.
def IsAdmin(func):
    @wraps(func)
    def wrap(*args, **kwargs):
        if "admin_logged_in" in session:
            return func(*args, **kwargs)
        return redirect(url_for('AdminLogin'))
    return wrap


# Dashboard page.
@app.route('/dashboard', methods=['GET', 'POST'])
@IsAdmin
def Dashboard(): 

    # In 'GET' request case.
    if request.method == 'GET':
        
        # Select all users from users table.
        users = list(FetchFromTheDatabse("SELECT * FROM users"))

        # Reverse users order to show up in the dashboard from newest to oldest.
        users.reverse()

        return render_template('dashboard.html', users=users)

    # In 'POST' request case.
    if request.method == 'POST':

        # Get the search value.
        searchValue = str(request.form['search'])

        # Get the users who got the access to the exam.
        usersIdWhoGotTheAccess = request.form.getlist('access')

        # Get all users who appear in the dashboard.
        dashboardUsersId = request.form.getlist('allUsers')
        dashboardUsers = []
        for userId in dashboardUsersId:
            dashboardUsers.append(FetchFromTheDatabseWithValue("SELECT * FROM users WHERE id = %s", userId))

        # Put the 'access' value in the database.
        for user in dashboardUsers:
            if str(user[0]['id']) in usersIdWhoGotTheAccess:
                PutChangesInDatabase("UPDATE users SET access = 1 WHERE id = %s", [str(user[0]['id'])])
            else:
                PutChangesInDatabase("UPDATE users SET access = 0 WHERE id = %s", [str(user[0]['id'])])

        # Check if admin searched for a user/s by name/number.
        if searchValue:
            # Get the search results from the database by phone/name.

            # Search in database by phone.
            users = FetchFromTheDatabseWithValue("SELECT * FROM users WHERE phone = %s", searchValue)
            if users:
                return render_template('dashboard.html', users=users)

            # Search in database by name.
            users = FetchFromTheDatabseWithValue("SELECT * FROM users WHERE name = %s", searchValue)
            if users:
                return render_template('dashboard.html', users=users)
            
            # If there is no results for the search, return the dashboard with no users.
            return render_template("dashboard.html")


        # Select all users with the correct 'access' value
        users = list(FetchFromTheDatabse("SELECT * FROM users"))

        # Reverse users order to show up in the dashboard from newest to oldest.
        users.reverse()

        return render_template("dashboard.html", users=users)


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
        if FetchFromTheDatabseWithValue("SELECT got_pre_a1 FROM users WHERE id = %s", session['user_id'])[0]['got_pre_a1']:
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
        testNumber = SearchInTheDatabaseWithValue("SELECT * FROM tests WHERE id = %s", session['user_id']) + 1
        
        # Insert the 'pre a1' test marks in the 'tests' table.
        PutChangesInDatabase("INSERT INTO tests(id, test_num, lpre_a1, rpre_a1, gpre_a1, fpre_a1, g2pre_a1, pre_a1) VALUES(%s, %s, %s, %s, %s, %s, %s, %s)",
        (session['user_id'], testNumber, listeningMarks, readingMarks, grammarMarks, functionalMarks, grammar2Marks, totalMarks))


        # If the user passed the test, redirect him to the next exam.
        if totalMarks >= 1:
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
        userRow = FetchFromTheDatabseWithValue("SELECT * FROM users WHERE id = %s", session['user_id'])[0]
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
        testNumber = SearchInTheDatabaseWithValue("SELECT * FROM tests WHERE id = %s", session['user_id'])
        
        # Update the 'A1' test marks in the 'tests' table.
        PutChangesInDatabase("UPDATE tests SET la1 = %s, ra1 = %s, va1 = %s, fa1 = %s, ga1 = %s, a1 = %s WHERE id = %s and test_num = %s",
        (listeningMarks, readingMarks, vocabularyMarks, functionalMarks, grammarMarks, totalMarks, session['user_id'], testNumber))

        # If the user passed the test, redirect him to the next exam.
        if totalMarks >= 1:
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
        userRow = FetchFromTheDatabseWithValue("SELECT * FROM users WHERE id = %s", session['user_id'])[0]
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
        testNumber = SearchInTheDatabaseWithValue("SELECT * FROM tests WHERE id = %s", session['user_id'])
        
        # Update the 'A1' test marks in the 'tests' table.
        PutChangesInDatabase("UPDATE tests SET la2 = %s, ra2 = %s, va2 = %s, fa2 = %s, ga2 = %s, a2 = %s WHERE id = %s and test_num = %s",
        (listeningMarks, readingMarks, vocabularyMarks, functionalMarks, grammarMarks, totalMarks, session['user_id'], testNumber))

        # If the user passed the test, redirect him to the next exam.
        if totalMarks >= 1:
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
        userRow = FetchFromTheDatabseWithValue("SELECT * FROM users WHERE id = %s", session['user_id'])[0]
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
        testNumber = SearchInTheDatabaseWithValue("SELECT * FROM tests WHERE id = %s", session['user_id'])
        
        # Update the 'A1' test marks in the 'tests' table.
        PutChangesInDatabase("UPDATE tests SET lb1 = %s, rb1 = %s, phb1 = %s, fb1 = %s, gb1 = %s, b1 = %s WHERE id = %s and test_num = %s",
        (listeningMarks, readingMarks, phoneticsMarks, functionalMarks, grammarMarks, totalMarks, session['user_id'], testNumber))

        # If the user passed the test, redirect him to the next exam.
        if totalMarks >= 1:
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
        userRow = FetchFromTheDatabseWithValue("SELECT * FROM users WHERE id = %s", session['user_id'])[0]
        # if not userRow['got_b1'] or not userRow['f_b1'] or userRow['got_b2']:
        #     return redirect(url_for("Logout"))

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
        testNumber = SearchInTheDatabaseWithValue("SELECT * FROM tests WHERE id = %s", session['user_id'])
        
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

    Logout()

    return render_template('test_results.html', tests=userTests)
     
    
# Tests results page for admins.
@app.route('/tests_results/<string:id>')
@IsAdmin
def TestResults(id):

    # Get user tests.
    userTests = list(FetchFromTheDatabseWithValue("SELECT * FROM tests WHERE id = %s", [id]))
    userTests.reverse()

    userRow = FetchFromTheDatabse("SELECT * FROM users WHERE id = {0}".format(id))[0]

    return render_template('test_results.html', tests=userTests, userRow=userRow)

# Delete user.
@app.route('/delete/<string:id>/')
@IsAdmin
def Delete(id):
   
    # Delete the user row from 'users' table in the database.
    PutChangesInDatabase("DELETE FROM users WHERE id = %s", [id])

    # Delete users tests from 'tests' table.
    for testNum in range(SearchInTheDatabaseWithValue("SELECT * FROM tests WHERE id = %s", [id])):
        PutChangesInDatabase("DELETE FROM tests WHERE id = %s and test_num = %s", (id, testNum+1))

    return redirect(url_for('Dashboard'))


@app.route("/moving_forward", methods=['GET', 'POST'])
@IsUserLoggedin
def MovingForward():

    # In 'GET' request case.
    if request.method == 'GET':
        
        for finshedTest, testName in zip(["f_b1", "f_a2", "f_a1", "f_pre_a1"], ["B1", "A2", "A1", "Pre_A1"]):
            if SearchInTheDatabase("SELECT * FROM users WHERE (id = {0}) and {1} = 1".format(session['user_id'], finshedTest)):
                testsNum = SearchInTheDatabase("SELECT * FROM tests WHERE (id = {0})".format(session['user_id']))
                lastExamGrades = FetchFromTheDatabse("SELECT * FROM tests WHERE (id = {0}) and (test_num = {1})".format(session['user_id'], testsNum))[0][testName.lower()]
                
                return render_template("moving_forward.html", text="Would you like to go to the next stage?", testName=testName, grades=lastExamGrades)

        return render_template("moving_forward.html", start="Start", text="Would you like to start Pre A1?")
    
    # In 'GET' request case.
    if request.method == 'POST':

        for finshedTest, testFunc in zip(["f_b1", "f_a2", "f_a1", "f_pre_a1"], ["TestB2", "TestB1", "TestA2", "TestA1"]):
            if SearchInTheDatabaseWithValue("SELECT * FROM users WHERE id = %s and " + finshedTest + " = 1", [session['user_id']]):
                return redirect(url_for(testFunc))

        return redirect(url_for("TestPreA1"))


@app.route("/download_users", methods=['GET', 'POST'])
def tt():
    n = ()

    # if request.method == 'POST':
    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM users")
    allusers = cur.fetchall()

    with open("file.csv", 'w', newline='') as f:
        thewriter = csv.writer(f)
        thewriter.writerow([
            'id', 'name', 'phone', 'email', 'date', 
            'Listening_Pre_A1', 'Reading_Pre_A1', 'Grammar_Pre_A1', 'Functional_language_Pre_A1', 'Grammar_Pre_A1', 'Pre_A1',
            'listening_A1', 'Reading_A1', 'Vocabulary_A1', 'Functional_language_A1', 'Grammar_A1', 'A1', 
            'listening_A2', 'Reading_A2', 'Vocabulary_A2', 'Functional_language_A2', 'Grammar_A2', 'A2', 
            'listening_B1', 'Reading_B1', 'phonetics_B1', 'Functional_language_B1', 'Grammar_B1', 'B1', 
            'listening_B2', 'Reading_B2', 'Vocabulary_B2', 'Functional_language_B2', 'Grammar_B2', 'B2', 
            ])

        for row in allusers:
            n = ()
            if row['admin'] == 0:
                for i in range(2, 10000):
                    try:
                        cur.execute("SELECT * FROM test%s_%s",( i, row['id']))
                        n = cur.fetchall()
                        #print(n, i, row['id'])

                    except Exception:
                        break
                        #print(n, i, row['id'])


                if n != ():
                    #print("got in if")
                    thewriter.writerow([
                        row['id'], row['name'], row['phone'], row['email'],  n[0]['date'],
                        n[0]['lpre_a1'], n[0]['rpre_a1'], n[0]['gpre_a1'], n[0]['fpre_a1'], n[0]['g2pre_a1'], n[0]['pre_a1'],
                        n[0]['la1'], n[0]['ra1'], n[0]['va1'], n[0]['fa1'], n[0]['ga1'], n[0]['a1'],
                        n[0]['la2'], n[0]['ra2'], n[0]['va2'], n[0]['fa2'], n[0]['ga2'], n[0]['a2'],
                        n[0]['lb1'], n[0]['rb1'], n[0]['phb1'], n[0]['fb1'], n[0]['gb1'], n[0]['b1'], 
                        n[0]['lb2'], n[0]['rb2'], n[0]['vb2'], n[0]['fb2'], n[0]['gb2'], n[0]['b2']
                        ])
                else:
                    #print("got in else")
                    thewriter.writerow([
                        row['id'], row['name'], row['phone'], row['email'], str(row['date']),
                        row['lpre_a1'], row['rpre_a1'], row['gpre_a1'], row['fpre_a1'], row['g2pre_a1'], row['pre_a1'],
                        row['la1'], row['ra1'], row['va1'], row['fa1'], row['ga1'], row['a1'],
                        row['la2'], row['ra2'], row['va2'], row['fa2'], row['ga2'], row['a2'],
                        row['lb1'], row['rb1'], row['phb1'], row['fb1'], row['gb1'], row['b1'], 
                        row['lb2'], row['rb2'], row['vb2'], row['fb2'], row['gb2'], row['b2']
                        ])
                

    return send_file('file.csv',
    mimetype='text/csv',
    cache_timeout=0,
    attachment_filename='users.csv',
    as_attachment=True)


# @app.route('/p_pre_a1/<string:idd>/')
# def p_pre_a1(idd):
#     cur = mysql.connection.cursor()

#     cur.execute("SELECT * FROM users WHERE id = %s", [idd])
#     user = cur.fetchone()
    
#     if user['p_pre_a1'] == 0:
#         cur.execute("UPDATE users SET p_pre_a1 = 1 WHERE id = %s", [idd])
#         mysql.connection.commit()
#     else :
#         cur.execute("UPDATE users SET p_pre_a1 = 0 WHERE id = %s", [idd])
#         mysql.connection.commit()

#     cur.close()

#     return redirect(url_for('test_results', idd = user['id']))

# @app.route('/p_a1/<string:idd>/')
# def p_a1(idd):
#     cur = mysql.connection.cursor()

#     cur.execute("SELECT * FROM users WHERE id = %s", [idd])
#     user = cur.fetchone()
    
#     if user['p_a1'] == 0:
#         cur.execute("UPDATE users SET p_a1 = 1 WHERE id = %s", [idd])
#         mysql.connection.commit()
#     else :
#         cur.execute("UPDATE users SET p_a1 = 0 WHERE id = %s", [idd])
#         mysql.connection.commit()

#     cur.close()

#     return redirect(url_for('test_results', idd = user['id']))

# @app.route('/p_a2/<string:idd>/')
# def p_a2(idd):
#     cur = mysql.connection.cursor()

#     cur.execute("SELECT * FROM users WHERE id = %s", [idd])
#     user = cur.fetchone()
    
#     if user['p_a2'] == 0:
#         cur.execute("UPDATE users SET p_a2 = 1 WHERE id = %s", [idd])
#         mysql.connection.commit()
#     else :
#         cur.execute("UPDATE users SET p_a2 = 0 WHERE id = %s", [idd])
#         mysql.connection.commit()
    
#     cur.close()

#     return redirect(url_for('test_results', idd = user['id']))




# @app.route('/p_b1/<string:idd>/')
# def p_b1(idd):
#     cur = mysql.connection.cursor()

#     cur.execute("SELECT * FROM users WHERE id = %s", [idd])
#     user = cur.fetchone()
    
#     if user['p_b1'] == 0:
#         cur.execute("UPDATE users SET p_b1 = 1 WHERE id = %s", [idd])
#         mysql.connection.commit()
#     else :
#         cur.execute("UPDATE users SET p_b1 = 0 WHERE id = %s", [idd])
#         mysql.connection.commit()
#     cur.close()

#     return redirect(url_for('test_results', idd = user['id']))


# Reset password page.
@app.route('/reset_password/<string:id>/', methods=['GET', 'POST'])
@IsAdmin
def RestPassword(id):

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
        if passwordLen < 3:
            return render_template('reset_password.html', error = "Password is too short")
        if password != confirm:
            return render_template('reset_password.html', error = "Passwords didn't mach. Try again")

        # Crypt the password before put it in the database. 
        password = sha256_crypt.encrypt(str(password))

        # Updata user password.
        PutChangesInDatabase("UPDATE users SET password = %s WHERE id = %s", (password, id))

        return redirect(url_for('Dashboard'))
        

app.secret_key='secret123'

if __name__ == '__main__':
    
    if 'DB_USER' in os.environ:
        app.run()
    else:
        app.run(debug=True)