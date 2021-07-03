# # Check if trial admin logged in.
# def IsTrialAdmin(func):
#     @wraps(func)
#     def wrap(*args, **kwargs):
#         if "trial_admin_logged_in" in session:
#             return func(*args, **kwargs)
#         return redirect(url_for('TrialAdminLogin'))
#     return wrap









# # Check if user logged in.
# def IsTrialUserLoggedin(func):
#     @wraps(func)
#     def wrap(*args, **kwargs):
#         if "trial_user_logged_in" in session:
#             return func(*args, **kwargs)
#         return redirect(url_for('Logout'))
#     return wrap










# # Trial Admin login.
# @app.route("/trial/admin_login", methods=['GET', 'POST'])
# def TrialAdminLogin():
#     # In 'GET' request case.
#     if request.method == 'GET':
#         return render_template("trial_admin_login.html")

#     # In 'POST' request case.
#     if request.method == 'POST':

#         # Clear the session.
#         session.clear()

#         phone = str(request.form['phone'])
#         password = str(request.form['password'])
        
#         # Start connection with the database.
#         cur = mysql.connection.cursor()
        
#         # Check if the user existe.
#         admin = cur.execute("SELECT * FROM trial_admins WHERE phone = %s", [phone])
#         if not admin:
#             return render_template("trial_admin_login.html", error='Invalid login.')

#         # Select the admin row.
#         adminRow = cur.fetchone()

#         # Close the connection with the database.
#         cur.close()

#         # Verify the password.
#         verified = sha256_crypt.verify(password, adminRow['password'])
#         if not verified:
#             return render_template("trial_admin_login.html", error='Invalid password.')

#         # Check the validity of the admin.
#         if not adminRow['admin']:
#             return render_template("trial_admin_login.html", error='You are not an admin yet.')

#         session['trial_admin_logged_in'] = True
#         session['trial_admin_name'] = adminRow['name']
#         if adminRow['can_d']:
#             session["trial_admin_can_d"] = True

#         return redirect(url_for('TrialDashboard'))


# # Admin register page.
# @app.route('/trial/admin_register', methods=['GET', 'POST'])
# def TrialAdminRegister():

#     # In 'GET' request case.
#     if request.method == 'GET':
#         return render_template("trial_admin_register.html")

#     # In 'POST' request case.
#     if request.method == 'POST':

#         # Get the registration data from the form.
#         name = request.form['name']
#         phone = str(request.form['phone'])
#         password = request.form['password']
#         confirm = request.form['confirm']

#         # Check the correctness of the form fields.
#         if len(name) < 1 or len(name) > 50:
#             return render_template("trial_admin_register.html", error="Invalid name. Try again")

#         if len(phone) < 8 or len(phone) > 16:
#             return render_template("trial_admin_register.html", error="Invalid phone number. Try again")

#         if len(password) < 6:
#             return render_template("trial_admin_register.html", error="The password is too short. Try again") 
        
#         if len(password) > 50:
#             return render_template("trial_admin_register.html", error="The password is too long. Try again") 

#         if password != confirm:
#             return render_template("trial_admin_register.html", error="Passwords didn't mach. Try again")

#         # Check if the phone number is used.
#         if SearchInTheDatabase("SELECT * FROM trial_admins WHERE phone = " + phone):
#             return render_template("trial_admin_register.html", error="This phone number is allready used!")
        
#         # Crypt the password befor put it it on the database.
#         password = sha256_crypt.encrypt(str(password))
        
#         # Insert admin data in the 'admins' table.
#         PutChangesInDatabase("INSERT INTO trial_admins(name, phone, password) VALUES(%s, %s, %s)", (name, phone, password))
        
#         return redirect(url_for("TrialAdminLogin"))


# # Trial Dashboard page.
# @app.route('/trial/dashboard', methods=['GET', 'POST'])
# @IsTrialAdmin
# def TrialDashboard(): 

#     # In 'GET' request case.
#     if request.method == 'GET':
        
#         # Select all users from users table.
#         users = list(FetchFromTheDatabse("SELECT * FROM trial_users"))

#         # Reverse users order to show up in the dashboard from newest to oldest.
#         users.reverse()

#         return render_template('trial_dashboard.html', users=users)

#     # In 'POST' request case.
#     if request.method == 'POST':

#         # Get the search value.
#         searchValue = str(request.form['search'])

#         if searchValue:

#             # Get the search results from the database by phone/name.

#             # Search in database by phone.
#             users = list(FetchFromTheDatabse("SELECT * FROM trial_users WHERE phone LIKE '%{0}%'".format(searchValue)))
#             if users:
#                 users.reverse()
#                 return render_template('trial_dashboard.html', users=users)

#             # Search in database by name.
#             users = list(FetchFromTheDatabse("SELECT * FROM trial_users WHERE name LIKE '%{0}%'".format(searchValue)))
#             if users:
#                 users.reverse()
#                 return render_template('trial_dashboard.html', users=users)
            
#             # If there is no results for the search, return the dashboard with no users.
#             return render_template("trial_dashboard.html")


#         # Select all users with the correct 'access' value
#         users = list(FetchFromTheDatabse("SELECT * FROM trial_users"))

#         # Reverse users order to show up in the dashboard from newest to oldest.
#         users.reverse()

#         return render_template("trial_dashboard.html", users=users)


# # Trial login page.
# @app.route('/trial/login', methods=['GET', 'POST'])
# def TrialLogin():

#     # In 'GET' request case.
#     if request.method == 'GET':
#         return render_template('trial_login.html')

#     # In 'POST' request case.
#     if request.method == 'POST':

#         # Clear the session.
#         session.clear()

#         phone = request.form['phone']
#         password = request.form['password']

#         # Start connection with the database.
#         cur = mysql.connection.cursor()

#         # Check if the user existe.
#         user = cur.execute("SELECT * FROM trial_users WHERE phone = %s", [phone])
#         if not user:
#             return render_template("trial_login.html", error="Invalid login")

#         # Select the user row.
#         userRow = cur.fetchone()

#         # Close the connection with the database.
#         cur.close()

#         # Verify the password.
#         verified = sha256_crypt.verify(password, userRow['password'])
#         if not verified:
#             return render_template("trial_login.html", error="Incorrect password. Try again")

#         # Check if the user have access to the exam.
#         if not userRow['access']:
#             return render_template("trial_login.html", error="You do not have access yet.")
        
#         # Put user login variable in session.
#         session['trial_user_logged_in'] = True
#         session['trial_user_id'] = str(userRow['id'])

#         if userRow['p_b1']:
#             PutChangesInDatabase("UPDATE trial_users SET got_pre_a1 = 1, f_pre_a1 = 1, got_a1 = 1, f_a1 = 1, got_a2 = 1, f_a2 = 1, got_b1 = 1, f_b1 = 1 WHERE id = %s", [session['user_id']])
#             return redirect(url_for("TrialMovingForward"))
#         if userRow['p_a2']:
#             PutChangesInDatabase("UPDATE trial_users SET got_pre_a1 = 1, f_pre_a1 = 1, got_a1 = 1, f_a1 = 1, got_a2 = 1, f_a2 = 1 WHERE id = %s", [session['user_id']])
#             return redirect(url_for("TrialMovingForward"))
#         if userRow['p_a1']:
#             PutChangesInDatabase("UPDATE trial_users SET got_pre_a1 = 1, f_pre_a1 = 1, got_a1 = 1, f_a1 = 1 WHERE id = %s", [session['user_id']])
#             return redirect(url_for("TrialMovingForward"))
#         if userRow['p_pre_a1']:
#             PutChangesInDatabase("UPDATE trial_users SET got_pre_a1 = 1, f_pre_a1 = 1 WHERE id = %s", [session['user_id']])
#             return redirect(url_for("TrialMovingForward"))
        
#         return redirect(url_for("TrialMovingForward"))


# # Trial register page.
# @app.route('/trial/register', methods=['GET', 'POST'])
# def TrialRegister():

#     # In 'GET' request case.
#     if request.method == 'GET':
#         return render_template("trial_register.html")

#     # In 'POST' request case.
#     if request.method == 'POST':

#         # Get the registration data from the form.
#         name = request.form['name']
#         phone = str(request.form['phone'])
#         email = request.form['email']
#         password = request.form['password']
#         confirm = request.form['confirm']

#         # Check the correctness of the form fields.
#         if len(name) < 1 or len(name) > 50:
#             return render_template("trial_register.html", error="Invalid name. Try again")

#         if len(phone) < 8 or len(phone) > 16:
#             return render_template("trial_register.html", error="Invalid phone number. Try again")

#         if len(email) > 50:
#             return render_template("trial_register.html", error="Invalid Email. Try again")

#         if len(password) < 6:
#             return render_template("trial_register.html", error="The password is too short. Try again") 
        
#         if len(password) > 50:
#             return render_template("trial_register.html", error="The password is too long. Try again") 

#         if password != confirm:
#             return render_template("trial_register.html", error="Passwords didn't mach. Try again")

#         # Check if the phone number is used.
#         if SearchInTheDatabase("SELECT * FROM trial_users WHERE phone = " + phone):
#             return render_template("trial_register.html", error="This phone number is allready used!")
        
#         # Crypt the password befor put it it on the database.
#         password = sha256_crypt.encrypt(str(password))
        
#         try:
#             # Insert user data in the 'users' table.
#             PutChangesInDatabase("INSERT INTO trial_users(name, phone, email, password) VALUES(%s, %s, %s, %s)",
#             (name, phone, email, password))
#         except Exception as e:
#             print(e)

#         return redirect(url_for("TrialLogin"))


# @app.route("/trial/moving_forward", methods=['GET', 'POST'])
# @IsTrialUserLoggedin
# def TrialMovingForward():

#     # In 'GET' request case.
#     if request.method == 'GET':

#         tests = ["B1", "A2", "A1", "Pre_A1"]
#         for finshedTest, pastTestName in zip(["f_b1", "f_a2", "f_a1", "f_pre_a1"], tests):
#             if SearchInTheDatabase("SELECT * FROM trial_users WHERE (id = {0}) and {1} = 1".format(session['trial_user_id'], finshedTest)):
#                 testsNum = SearchInTheDatabase("SELECT * FROM trial_tests WHERE (id = {0})".format(session['trial_user_id']))
#                 lastExamGrades = FetchFromTheDatabse("SELECT * FROM trial_tests WHERE (id = {0}) and (test_num = {1})".format(session['trial_user_id'], testsNum))[0][pastTestName.lower()]
#                 return render_template("moving_forward.html", text="Go to the next stage (" + tests[tests.index(pastTestName) - 1] + ")" if pastTestName != "B1" else "Go to the next stage (B2)", pastTestName=pastTestName, grades=lastExamGrades)

#         return render_template("moving_forward.html", start="Start", text="Would you like to start Pre A1?")
    
#     # In 'GET' request case.
#     if request.method == 'POST':

#         for finshedTest, testFunc in zip(["f_b1", "f_a2", "f_a1", "f_pre_a1"], ["TrialTestB2", "TrialTestB1", "TrialTestA2", "TrialTestA1"]):
#             if SearchInTheDatabaseWithValue("SELECT * FROM trial_users WHERE id = %s and " + finshedTest + " = 1", [session['trial_user_id']]):
#                 return redirect(url_for(testFunc))

#         return redirect(url_for("TrialTestPreA1"))

# # Test 'Pre A1' page.
# @app.route("/trial_test_pre_A1", methods=['GET', 'POST'])
# @IsTrialUserLoggedin
# def TrialTestPreA1():

#     # In 'GET' request case.
#     if request.method == 'GET':
        
#         # Check if user got into 'pre_A1' test before.
#         if FetchFromTheDatabseWithValue("SELECT got_pre_a1 FROM trial_users WHERE id = %s", session['trial_user_id'])[0]['got_pre_a1']:
#             return redirect(url_for("Logout"))
#         PutChangesInDatabase("UPDATE trial_users SET got_pre_a1 = 1 WHERE id = %s", [session['trial_user_id']])
        
#         return render_template("test_pre_A1.html")

#     # In 'POST' request case.
#     if request.method == 'POST':

#         # Set in the database that: the user has finished the 'pre_A1" test.
#         PutChangesInDatabase("UPDATE trial_users SET f_pre_a1 = 1 WHERE id = %s", [session['trial_user_id']])

#         # The correct answers.
#         p1Answers = ['A', 'C', 'E', 'G']
#         p2Answers = ['B', 'C', 'A', 'B']
#         p3Answers = ['A', 'A', 'C', 'A']
#         p4Answers = ['B', 'A', 'B', 'C']
#         p5Answers = ['B', 'A', 'A', 'C', 'B', 'C', 'A', 'C']

#         # Initialize variables to represent the test marks.
#         totalMarks = 0
#         listeningMarks = 0
#         readingMarks = 0
#         grammarMarks = 0
#         functionalMarks = 0
#         grammar2Marks = 0
        
#         # Get user marks the 'listening' part.
#         listeningMarks = MarkingTheFourQuestionsTestPart(p1Answers, "listening")
#         totalMarks += listeningMarks

#         # Get user marks the 'reading' part.
#         readingMarks = MarkingTheOneQuestionTestPart(p2Answers, "reading")
#         totalMarks += readingMarks

#         # Get user marks the 'grammar' part.
#         grammarMarks = MarkingTheOneQuestionTestPart(p3Answers, "grammar")
#         totalMarks += grammarMarks

#         # Get user marks the 'functional' part.
#         functionalMarks = MarkingTheOneQuestionTestPart(p4Answers, "functional_language")
#         totalMarks += functionalMarks

#         # Get user marks the 'grammar2' part.
#         grammar2Marks = MarkingTheOneQuestionTestPart(p5Answers, "2grammar")
#         totalMarks += grammar2Marks

#         # Get the test numder for the user.
#         testNumber = SearchInTheDatabaseWithValue("SELECT * FROM trial_tests WHERE id = %s", session['trial_user_id']) + 1
        
#         # Insert the 'pre a1' test marks in the 'tests' table.
#         PutChangesInDatabase("INSERT INTO trial_tests(id, test_num, lpre_a1, rpre_a1, gpre_a1, fpre_a1, g2pre_a1, pre_a1) VALUES(%s, %s, %s, %s, %s, %s, %s, %s)",
#         (session['trial_user_id'], testNumber, listeningMarks, readingMarks, grammarMarks, functionalMarks, grammar2Marks, totalMarks))


#         # If the user passed the test, redirect him to the next exam.
#         if totalMarks >= 19:
#             return redirect(url_for("MovingForward"))
        
#         # If the user didn't pass the test, redirect him to the 'UserResults' page.
#         return redirect(url_for("TrialUserResults"))


# # Test 'A1' page.
# @app.route("/trial_test_A1", methods=['GET', 'POST'])
# @IsTrialUserLoggedin
# def TrialTestA1():

#     # In 'GET' request case.
#     if request.method == 'GET':
        
#         # Check if the user can take the test.
#         userRow = FetchFromTheDatabseWithValue("SELECT * FROM trial_users WHERE id = %s", session['trial_user_id'])[0]
#         if not userRow['got_pre_a1'] or not userRow['f_pre_a1'] or userRow['got_a1']:
#             return redirect(url_for("Logout"))

#         PutChangesInDatabase("UPDATE trial_users SET got_a1 = 1 WHERE id = %s", [session['trial_user_id']])
        
#         return render_template("test_A1.html")

#     # In 'POST' request case.
#     if request.method == 'POST':

#         # Set in the database that: the user has finished the 'A1" test.
#         PutChangesInDatabase("UPDATE trial_users SET f_a1 = 1 WHERE id = %s", [session['trial_user_id']])

#         # The correct answers.
#         p1Answers = ['A', 'D', 'B', 'B']
#         p2Answers = ['D', 'D', 'D', 'C']
#         p3Answers = ['D', 'B', 'C', 'C']
#         p4Answers = ['A', 'C', 'C', 'A']
#         p5Answers = ['B', 'D', 'A', 'C', 'D', 'B', 'A', 'C']

#         # Initialize variables to represent the test marks.
#         totalMarks = 0
#         listeningMarks = 0
#         readingMarks = 0
#         vocabularyMarks = 0
#         functionalMarks = 0
#         grammarMarks = 0

#         # Get user marks the 'listening' part.
#         listeningMarks = MarkingTheOneQuestionTestPart(p1Answers, "listening")
#         totalMarks += listeningMarks

#         # Get user marks the 'reading' part.
#         readingMarks = MarkingTheOneQuestionTestPart(p2Answers, "reading")
#         totalMarks += readingMarks

#         # Get user marks the 'vocabulary' part.
#         vocabularyMarks = MarkingTheOneQuestionTestPart(p3Answers, "vocabulary")
#         totalMarks += vocabularyMarks

#         # Get user marks the 'functional' part.
#         functionalMarks = MarkingTheOneQuestionTestPart(p4Answers, "functional_language")
#         totalMarks += functionalMarks

#         # Get user marks the 'grammar' part.
#         grammarMarks = MarkingTheOneQuestionTestPart(p5Answers, "grammar")
#         totalMarks += grammarMarks

#         # Get the test numder for the user.
#         testNumber = SearchInTheDatabaseWithValue("SELECT * FROM trial_tests WHERE id = %s", session['trial_user_id'])
        
#         # Update the 'A1' test marks in the 'tests' table.
#         PutChangesInDatabase("UPDATE trial_tests SET la1 = %s, ra1 = %s, va1 = %s, fa1 = %s, ga1 = %s, a1 = %s WHERE id = %s and test_num = %s",
#         (listeningMarks, readingMarks, vocabularyMarks, functionalMarks, grammarMarks, totalMarks, session['trial_user_id'], testNumber))

#         # If the user passed the test, redirect him to the next exam.
#         if totalMarks >= 19:
#             return redirect(url_for("MovingForward"))
        
#         # If the user didn't pass the test, redirect him to the 'UserResults' page.
#         return redirect(url_for("TrialUserResults"))


# # Test 'A2' page.
# @app.route("/trial_test_A2", methods=['GET', 'POST'])
# @IsTrialUserLoggedin
# def TrialTestA2():

#     # In 'GET' request case.
#     if request.method == 'GET':
        
#         # Check if the user can take the test.
#         userRow = FetchFromTheDatabseWithValue("SELECT * FROM trial_users WHERE id = %s", session['trial_user_id'])[0]
#         if not userRow['got_a1'] or not userRow['f_a1'] or userRow['got_a2']:
#             return redirect(url_for("Logout"))

#         PutChangesInDatabase("UPDATE trial_users SET got_a2 = 1 WHERE id = %s", [session['trial_user_id']])
        
#         return render_template("test_A2.html")

#     # In 'POST' request case.
#     if request.method == 'POST':

#         # Set in the database that: the user has finished the 'A1" test.
#         PutChangesInDatabase("UPDATE trial_users SET f_a2 = 1 WHERE id = %s", [session['trial_user_id']])
        
#         # The correct answers.
#         p1Answers = ['B', 'D', 'G', 'J']
#         p2Answers = ['D', 'C', 'B', 'D']
#         p3Answers = ['A', 'C', 'A', 'C']
#         p4Answers = ['A', 'D', 'B', 'C']
#         p5Answers = ['A', 'D', 'B', 'C', 'A', 'A', 'A', 'A']

#         # Initialize variables to represent the test marks.
#         totalMarks = 0
#         listeningMarks = 0
#         readingMarks = 0
#         vocabularyMarks = 0
#         functionalMarks = 0
#         grammarMarks = 0

#         # Get user marks the 'listening' part.
#         listeningMarks = MarkingTheFourQuestionsTestPart(p1Answers, "listening")
#         totalMarks += listeningMarks

#         # Get user marks the 'reading' part.
#         readingMarks = MarkingTheOneQuestionTestPart(p2Answers, "reading")
#         totalMarks += readingMarks

#         # Get user marks the 'vocabulary' part.
#         vocabularyMarks = MarkingTheOneQuestionTestPart(p3Answers, "vocabulary")
#         totalMarks += vocabularyMarks

#         # Get user marks the 'functional' part.
#         functionalMarks = MarkingTheOneQuestionTestPart(p4Answers, "functional_language")
#         totalMarks += functionalMarks

#         # Get user marks the 'grammar' part.
#         grammarMarks = MarkingTheOneQuestionTestPart(p5Answers, "grammar")
#         totalMarks += grammarMarks

#         # Get the test numder for the user.
#         testNumber = SearchInTheDatabaseWithValue("SELECT * FROM trial_tests WHERE id = %s", session['trial_user_id'])
        
#         # Update the 'A1' test marks in the 'tests' table.
#         PutChangesInDatabase("UPDATE trial_tests SET la2 = %s, ra2 = %s, va2 = %s, fa2 = %s, ga2 = %s, a2 = %s WHERE id = %s and test_num = %s",
#         (listeningMarks, readingMarks, vocabularyMarks, functionalMarks, grammarMarks, totalMarks, session['trial_user_id'], testNumber))

#         # If the user passed the test, redirect him to the next exam.
#         if totalMarks >= 19:
#             return redirect(url_for("MovingForward"))
        
#         # If the user didn't pass the test, redirect him to the 'UserResults' page.
#         return redirect(url_for("TrialUserResults"))
        

# # Test 'B1' page.
# @app.route("/trial_test_B1", methods=['GET', 'POST'])
# @IsTrialUserLoggedin
# def TrialTestB1():

#     # In 'GET' request case.
#     if request.method == 'GET':
        
#         # Check if the user can take the test.
#         userRow = FetchFromTheDatabseWithValue("SELECT * FROM trial_users WHERE id = %s", session['trial_user_id'])[0]
#         if not userRow['got_a2'] or not userRow['f_a2'] or userRow['got_b1']:
#             return redirect(url_for("Logout"))

#         PutChangesInDatabase("UPDATE trial_users SET got_b1 = 1 WHERE id = %s", [session['trial_user_id']])
        
#         return render_template("test_B1.html")

#     # In 'POST' request case.
#     if request.method == 'POST':

#         # Set in the database that: the user has finished the 'A1" test.
#         PutChangesInDatabase("UPDATE trial_users SET f_b1 = 1 WHERE id = %s", [session['trial_user_id']])
        
#         # The correct answers.
#         p1Answers = ['A', 'C', 'D', 'G']
#         p2Answers = ['A', 'B', 'C', 'B']
#         p3Answers = ['C', 'B', 'A', 'B']
#         p4Answers = ['C', 'C', 'B', 'A']
#         p5Answers = ['A', 'B', 'B', 'B', 'B', 'B', 'A', 'A']

#         # Initialize variables to represent the test marks.
#         totalMarks = 0
#         listeningMarks = 0
#         readingMarks = 0
#         phoneticsMarks = 0
#         functionalMarks = 0
#         grammarMarks = 0

#         # Get user marks the 'listening' part.
#         listeningMarks = MarkingTheFourQuestionsTestPart(p1Answers, "listening")
#         totalMarks += listeningMarks

#         # Get user marks the 'reading' part.
#         readingMarks = MarkingTheOneQuestionTestPart(p2Answers, "reading")
#         totalMarks += readingMarks

#         # Get user marks the 'phonetics' part.
#         phoneticsMarks = MarkingTheOneQuestionTestPart(p3Answers, "phonetics")
#         totalMarks += phoneticsMarks

#         # Get user marks the 'functional' part.
#         functionalMarks = MarkingTheOneQuestionTestPart(p4Answers, "functional_language")
#         totalMarks += functionalMarks

#         # Get user marks the 'grammar' part.
#         grammarMarks = MarkingTheOneQuestionTestPart(p5Answers, "grammar")
#         totalMarks += grammarMarks

#         # Get the test numder for the user.
#         testNumber = SearchInTheDatabaseWithValue("SELECT * FROM trial_tests WHERE id = %s", session['trial_user_id'])
        
#         # Update the 'A1' test marks in the 'tests' table.
#         PutChangesInDatabase("UPDATE trial_tests SET lb1 = %s, rb1 = %s, phb1 = %s, fb1 = %s, gb1 = %s, b1 = %s WHERE id = %s and test_num = %s",
#         (listeningMarks, readingMarks, phoneticsMarks, functionalMarks, grammarMarks, totalMarks, session['trial_user_id'], testNumber))

#         # If the user passed the test, redirect him to the next exam.
#         if totalMarks >= 19:
#             return redirect(url_for("MovingForward"))
        
#         # If the user didn't pass the test, redirect him to the 'UserResults' page.
#         return redirect(url_for("TrialUserResults"))


# # Test 'B2' page.
# @app.route("/trial_test_B2", methods=['GET', 'POST'])
# @IsTrialUserLoggedin
# def TrialTestB2():

#     # In 'GET' request case.
#     if request.method == 'GET':
        
#         # Check if the user can take the test.
#         userRow = FetchFromTheDatabseWithValue("SELECT * FROM trial_users WHERE id = %s", session['trial_user_id'])[0]
#         if not userRow['got_b1'] or not userRow['f_b1'] or userRow['got_b2']:
#             return redirect(url_for("Logout"))

#         PutChangesInDatabase("UPDATE trial_users SET got_b2 = 1 WHERE id = %s", [session['trial_user_id']])
        
#         return render_template("test_B2.html")

#     # In 'POST' request case.
#     if request.method == 'POST':

#         p1Answers = ['A', 'C', 'G', 'H']
#         p2Answers = ['A', 'C', 'E', 'F']
#         p3Answers = ['A', 'B', 'C', 'A']
#         p4Answers = ['B', 'A', 'A', 'A']
#         p5Answers = ['A', 'A', 'B', 'A', 'A', 'A', 'B', 'A']

#         # Initialize variables to represent the test marks.
#         totalMarks = 0
#         listeningMarks = 0
#         readingMarks = 0
#         vocabularyMarks = 0
#         functionalMarks = 0
#         grammarMarks = 0

#         # Get user marks the 'listening' part.
#         listeningMarks = MarkingTheFourQuestionsTestPart(p1Answers, "listening")
#         totalMarks += listeningMarks

#         # Get user marks the 'reading' part.
#         readingMarks = MarkingTheFourQuestionsTestPart(p2Answers, "reading")
#         totalMarks += readingMarks

#         # Get user marks the 'phonetics' part.
#         vocabularyMarks = MarkingTheOneQuestionTestPart(p3Answers, "vocabulary")
#         totalMarks += vocabularyMarks

#         # Get user marks the 'functional' part.
#         functionalMarks = MarkingTheOneQuestionTestPart(p4Answers, "functional_language")
#         totalMarks += functionalMarks

#         # Get user marks the 'grammar' part.
#         grammarMarks = MarkingTheOneQuestionTestPart(p5Answers, "grammar")
#         totalMarks += grammarMarks

#         # Get the test numder for the user.
#         testNumber = SearchInTheDatabaseWithValue("SELECT * FROM trial_tests WHERE id = %s", session['trial_user_id'])
        
#         # Update the 'A1' test marks in the 'tests' table.
#         PutChangesInDatabase("UPDATE trial_tests SET lb2 = %s, rb2 = %s, vb2 = %s, fb2 = %s, gb2 = %s, b2 = %s WHERE id = %s and test_num = %s",
#         (listeningMarks, readingMarks, vocabularyMarks, functionalMarks, grammarMarks, totalMarks, session['trial_user_id'], testNumber))

#         return redirect(url_for("TrialUserResults"))


# # Tests results page for user.
# @app.route("/trial/user_results")
# @IsTrialUserLoggedin
# def TrialUserResults():

#     # Get user tests.
#     userTests = list(FetchFromTheDatabseWithValue("SELECT * FROM trial_tests WHERE id = %s", [session['trial_user_id']]))
#     userTests.reverse()

#     # Get user data
#     userRow = FetchFromTheDatabseWithValue("SELECT name, phone, email, date FROM trial_users WHERE id = %s", [session['trial_user_id']])[0]

#     Logout()

#     return render_template('test_results.html', tests=userTests, userRow=userRow)
     
    
# # Tests results page for admins.
# @app.route('/trial/tests_results/<string:id>')
# @IsTrialAdmin
# def TrialTestsResults(id):

#     # Get user tests.
#     userTests = list(FetchFromTheDatabseWithValue("SELECT * FROM trial_tests WHERE id = %s", [id]))
#     userTests.reverse()

#     userRow = FetchFromTheDatabse("SELECT * FROM trial_users WHERE id = {0}".format(id))[0]

#     return render_template('test_results.html', tests=userTests, userRow=userRow)

# # Delete user.
# @app.route('/trial/delete/<string:id>/')
# @IsTrialAdmin
# def TrialDelete(id):

#     # Check if the admin is allowed to delete users.
#     if "trial_admin_can_d" in session:

#         # Delete the user row from 'users' table in the database.
#         PutChangesInDatabase("DELETE FROM trial_users WHERE id = %s", [id])

#         # Delete users tests from 'tests' table.
#         for testNum in range(SearchInTheDatabaseWithValue("SELECT * FROM trial_tests WHERE id = %s", [id])):
#             PutChangesInDatabase("DELETE FROM tria_tests WHERE id = %s and test_num = %s", (id, testNum+1))

#     return redirect(url_for('TrialDashboard'))


# @app.route("/trial/dashboard/<user_id>/set-access", methods=['POST'])
# @IsTrialAdmin
# def TrialSetAccess(user_id):
#     accessValue = request.get_json()['access']

#     PutChangesInDatabase("UPDATE trial_users SET access = %s WHERE id = %s", (accessValue, user_id))

#     return redirect(url_for("TrialDashboard"))


print('\\')