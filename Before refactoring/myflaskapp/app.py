from flask import Flask, render_template, url_for, flash, redirect, session, request, logging
from flask_mysqldb import MySQL
from wtforms import Form, StringField, TextAreaField, PasswordField, validators
from passlib.hash import sha256_crypt
from functools import wraps
from flask_sqlalchemy import SQLAlchemy
import time
import datetime
import csv
from flask import send_file


#app = Flask(__name__, static_url_path='/static')
app = Flask(__name__, static_url_path="", static_folder="templates/static")

app.config["MYSQL_HOST"] = "localhost"
app.config["MYSQL_USER"] = "root"
app.config["MYSQL_PASSWORD"] = "M01019056637m"
app.config["MYSQL_DB"] = "passion"
app.config["MYSQL_CURSORCLASS"] = "DictCursor"

# app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql://scott:tiger@localhost/mydatabase'
# db = SQLAlchemy(app)



mysql = MySQL(app)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form['name']
        phone = str(request.form['phone'])
        email = request.form['email']
        password = request.form['password']
        confirm = request.form['confirm']

        cur = mysql.connection.cursor()
        
        if password == confirm:
            if len(name) >= 1 and len(name) < 100:
                if len(phone) >= 8 and len(phone) < 16:
                    if len(email) > 99:
                        return render_template("register.html", msg="Invalid Email")

                    result = cur.execute("SELECT * FROM users WHERE phone = %s", [phone])
                    if result > 0:
                        return render_template("register.html", msg="This phone number is allready used!")
                    if len(str(password)) >= 1 :

                        password = sha256_crypt.encrypt(str(password))

                        # Create cursor
                        

                        # Execute query
                        cur.execute("INSERT INTO users(name, phone, email, password) VALUES(%s, %s, %s, %s)", (name, phone, email, password))

                        # Commit to DB
                        mysql.connection.commit()

                        # Close connection
                        cur.close()
                    else: return render_template("register.html", msg="Invalid password")
                else: return render_template("register.html", msg="Invalid phone number")
            else: return render_template("register.html", msg="Name must have at least one character")

        else:
            return render_template("register.html", msg="Passwords didn't mach. Try again")

        return redirect(url_for("log"))
    return render_template("register.html")

error=''

def got_once_pre_A1(test_l):
    global error
    @wraps(test_l)
    def wrap(*args, **kwargs):
        if 'started_pre_A1' not in session:
            return test_l(*args, **kwargs)
        elif 'started_pre_A1' in session and 'started_pre_A1_2' not in session:
            session['started_pre_A1_2'] = True
            return test_l(*args, **kwargs)
        else:
            return redirect(url_for('log'))
    return wrap

def got_once_A1(test_l):
    global error
    @wraps(test_l)
    def wrap(*args, **kwargs):
        if 'finished_pre_A1' not in session:
            return test_l(*args, **kwargs)
        elif 'finished_pre_A1' in session and 'finished_pre_A1_2' not in session:
            session['finished_pre_A1_2'] = True
            return test_l(*args, **kwargs)
        else:
            return redirect(url_for('log'))
    return wrap

def got_once_A2(test_l):
    global error
    @wraps(test_l)
    def wrap(*args, **kwargs):
        if 'finished_A1' not in session:
            return test_l(*args, **kwargs)
        elif 'finished_A1' in session and 'finished_A1_2' not in session:
            session['finished_A1_2'] = True
            return test_l(*args, **kwargs)
        else:
            return redirect(url_for('log'))
    return wrap

def got_once_B1(test_l):
    global error
    @wraps(test_l)
    def wrap(*args, **kwargs):
        if 'finished_A2' not in session:
            return test_l(*args, **kwargs)
        elif 'finished_A2' in session and 'finished_A2_2' not in session:
            session['finished_A2_2'] = True
            return test_l(*args, **kwargs)
        else:
            return redirect(url_for('log'))
    return wrap

def got_once_B2(test_l):
    global error
    @wraps(test_l)
    def wrap(*args, **kwargs):
        if 'finished_B1' not in session:
            return test_l(*args, **kwargs)
        elif 'finished_B1' in session and 'finished_B1_2' not in session:
            session['finished_B1_2'] = True
            return test_l(*args, **kwargs)
        else:
            return redirect(url_for('log'))
    return wrap

def is_logged_in(a):
    global error
    @wraps(a)
    def wrap(*args, **kwargs):
        if 'logged_in' in session and 'admin_phone' in session:
            return a(*args, **kwargs)
        else:
            
            return redirect(url_for('admin_login'))
    return wrap

def notFall(r):
    global error
    @wraps(r)
    def wrap(*args, **kwargs):
        if 'fall' not in session:
            return r(*args, **kwargs)
        else:
            
            return redirect(url_for('fall'))
    return wrap

def is_logged_inu(b):
    global error
    @wraps(b)
    def wrap(*args, **kwargs):
        if 'logged_in' in session and 'phone' in session:
            return b(*args, **kwargs)
        else:
            
            return redirect(url_for('log'))
    return wrap

def m(m):
    global error
    @wraps(m)
    def wrap(*args, **kwargs):
        if 'got_into_m' in session and 'got_into_mm' in session:
            return redirect(url_for('logout'))
        elif 'got_into_m' in session:
             session['got_into_mm'] = True
        else:
            session['got_into_m'] = True

        if 'started_pre_A1' not in session and 'pass1' not in session and 'finished_pre_A1' not in session and 'pass2' not in session and 'pass3' not in session and 'pass4' not in session and 'passAll' not in session:
            return m(*args, **kwargs)
        else:
            
            return redirect(url_for('logout'))
    return wrap

def m1(m):
    global error
    @wraps(m)
    def wrap(*args, **kwargs):
        if 'got_into_m1' in session and 'got_into_mm1' in session:
            return redirect(url_for('logout'))
        elif 'got_into_m1' in session:
             session['got_into_mm1'] = True
        else:
            session['got_into_m1'] = True

        if 'pass1' in session and 'finished_pre_A1' not in session and 'pass2' not in session and 'pass3' not in session and 'pass4' not in session and 'passAll' not in session:
            return m(*args, **kwargs)
        else:
            
            return redirect(url_for('logout'))
    return wrap

def m2(m):
    global error
    @wraps(m)
    def wrap(*args, **kwargs):
        if 'got_into_m2' in session and 'got_into_mm2' in session:
            return redirect(url_for('logout'))
        elif 'got_into_m2' in session:
             session['got_into_mm2'] = True
        else:
            session['got_into_m2'] = True
            
        if 'pass1' in session and 'finished_A1' not in session and 'pass2' in session and 'pass3' not in session and 'pass4' not in session and 'passAll' not in session:
            return m(*args, **kwargs)
        else:
            
            return redirect(url_for('logout'))
    return wrap

def m3(m):
    global error
    @wraps(m)
    def wrap(*args, **kwargs):
        if 'got_into_m3' in session and 'got_into_mm3' in session:
            return redirect(url_for('logout'))
        elif 'got_into_m3' in session:
             session['got_into_mm3'] = True
        else:
            session['got_into_m3'] = True
            
        if 'pass1' in session and 'finished_A2' not in session and 'pass2' in session and 'pass3'  in session and 'pass4' not in session and 'passAll' not in session:
            return m(*args, **kwargs)
        else:
            
            return redirect(url_for('logout'))
    return wrap

def m4(m):
    global error
    @wraps(m)
    def wrap(*args, **kwargs):
        if 'got_into_m4' in session and 'got_into_mm4' in session:
            return redirect(url_for('logout'))
        elif 'got_into_m4' in session:
             session['got_into_mm4'] = True
        else:
            session['got_into_m4'] = True
            
        if 'pass1' in session and 'finished_B1' not in session and 'pass2' in session and 'pass3'  in session and 'pass4' in session and 'passAll' not in session:
            return m(*args, **kwargs)
        else:
            
            return redirect(url_for('logout'))
    return wrap




def passp(v):
    global error
    @wraps(v)
    def wrap(*args, **kwargs):
        if 'passAll' in session:
            return redirect(url_for('test_B2'))
        if 'pass4' in session:
            return redirect(url_for('test_B1'))
        if 'pass3' in session:
            return redirect(url_for('test_A2'))
        if 'pass2' in session:
            return redirect(url_for('test_A1'))
        if 'pass1' in session:
            return redirect(url_for('test_pre_A1'))
        return v(*args, **kwargs)
    return wrap

def pass1(c):
    global error
    @wraps(c)
    def wrap(*args, **kwargs):
        if 'pass1' in session:
            if 'passAll' in session:
                return redirect(url_for('test_B2'))
            if 'pass4' in session:
                return redirect(url_for('test_B1'))
            if 'pass3' in session:
                return redirect(url_for('test_A2'))
            if 'pass2' in session:
                return redirect(url_for('test_A1'))
            return c(*args, **kwargs)
        else:
            
            return redirect(url_for('test_pre_A1'))
    return wrap

def pass2(d):
    global error
    @wraps(d)
    def wrap(*args, **kwargs):
        if 'pass2' in session:
            if 'passAll' in session:
                return redirect(url_for('test_B2'))
            if 'pass4' in session:
                return redirect(url_for('test_B1'))
            if 'pass3' in session:
                return redirect(url_for('test_A2'))
            return d(*args, **kwargs)
        else:
            
            return redirect(url_for('test_A1'))
    return wrap

def pass3(e):
    global error
    @wraps(e)
    def wrap(*args, **kwargs):
        if 'pass3' in session:
            if 'passAll' in session:
                return redirect(url_for('test_B2'))
            if 'pass4' in session:
                return redirect(url_for('test_B1'))
            return e(*args, **kwargs)
        else:
            
            return redirect(url_for('test_A2'))
    return wrap

def pass4(h):
    global error
    @wraps(h)
    def wrap(*args, **kwargs):
        if 'pass4' in session:
            return h(*args, **kwargs)
        else:
            
            return redirect(url_for('test_B1'))
    return wrap



h = 0 
d = 0
dt_stringe = ''
ort = 0
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def log():
    global error
    global ort
    global h
    global d
    d = 0
    ort = 0
    h = 0

    if request.method == 'POST':
        phone = request.form['phone']
        password = request.form['password']
        error = "Invalid login"
        access = 1

        cur = mysql.connection.cursor()

        admin = cur.execute("SELECT * FROM users WHERE phone = %s AND admin = %b", [phone, 1])

        if admin == 0:
            user = cur.execute("SELECT * FROM users WHERE phone = %s AND access = %b", [phone, 1])
            
            if user == 0:
                user = cur.execute("SELECT * FROM users WHERE phone = %s", [phone])
                access = 0

                if user == 0:
                    return render_template("log.html", error=error)

        data = cur.fetchone()
        password_crypty = data['password']

        result1 = sha256_crypt.verify(password, password_crypty)

        
        
        if result1 and admin > 0:
            session['logged_in'] = True
            session['admin_phone'] = phone
            cur.execute("SELECT * FROM users WHERE phone = %s", [phone])
            session['admin_row'] = cur.fetchone()
            return redirect(url_for('dashboard'))

        if admin > 0:
            error = "Invalid Admin Password"
            return render_template("log.html", error=error)

        if result1 and user > 0 and access == 1:
            session['logged_in'] = True
            session['phone'] = phone
            session['id'] = cur.execute("SELECT id FROM users WHERE phone = %s", [str(phone)])
            session['id'] = cur.fetchone()

            
            cur.execute("SELECT * FROM users WHERE phone = %s", [str(phone)])
            allow = cur.fetchone() 
            if allow['p_b1'] == 1:

                session['pass1'] = True
                session['started_pre_A1'] = True
                session['pass2'] = True
                session['finished_pre_A1'] = True
                session['pass3'] = True
                session['finished_A1'] = True
                session['pass4'] = True
                session['finished_A2'] = True


                for i in range(2, 10000):
                    try:
                        print(i)
                        cur.execute("SELECT * FROM test%s_%s", (i, session['id']['id']))
                    except Exception:
                        h = i-1
                        break
                if h > 1:
                    d = 1
                    ort = 1
                    

                return redirect(url_for('move_to_b2'))

            if allow['p_a2'] == 1:

                session['pass1'] = True
                session['started_pre_A1'] = True
                session['pass2'] = True
                session['finished_pre_A1'] = True
                session['pass3'] = True
                session['finished_A1'] = True


                for i in range(2, 10000):
                    try:
                        print(i)
                        cur.execute("SELECT * FROM test%s_%s", (i, session['id']['id']))
                    except Exception:
                        h = i-1
                        break
                if h > 1:
                    d = 1
                    ort = 1
                    

                return redirect(url_for('move_to_b1'))

            if allow['p_a1'] == 1:

                session['pass1'] = True
                session['started_pre_A1'] = True
                session['pass2'] = True
                session['finished_pre_A1'] = True


                for i in range(2, 10000):
                    try:
                        print(i)
                        cur.execute("SELECT * FROM test%s_%s", (i, session['id']['id']))
                    except Exception:
                        h = i-1
                        break
                if h > 1:
                    d = 1
                    ort = 1
                    

                return redirect(url_for('move_to_a2'))

            if allow['p_pre_a1'] == 1:

                session['pass1'] = True
                session['started_pre_A1'] = True

                for i in range(2, 10000):
                    try:
                        print(i)
                        cur.execute("SELECT * FROM test%s_%s", (i, session['id']['id']))
                    except Exception:
                        h = i-1
                        break
                if h > 1:
                    d = 1
                    ort = 1
                    

                return redirect(url_for('move_to_a1'))
            return redirect(url_for("move_to_pre_a1"))

        if result1 and user:
            error = "You do not have access yet"
            return render_template("log.html", error=error)
        
        return render_template("log.html", error=error)
        cur.close()

    logout()
    return render_template('log.html')
    





# Logout
@app.route('/logout')
def logout():
    global h
    global d
    print(h, d)
    cur = mysql.connection.cursor()
    try:
        cur.execute("UPDATE users SET access = 0 WHERE id = %s", [session['id']['id']])
        mysql.connection.commit()
    except Exception:
        pass
    
    session.clear()
    return redirect(url_for('log'))

search =''
users = ()
@app.route('/dashboard', methods=['GET', 'POST'])
@is_logged_in
def dashboard():
    global search
    global users
    

    if request.method == 'POST':
        search = str(request.form['search'])
        if search:
            print("sihfliaksgfhajgskljg")
            cur = mysql.connection.cursor()
    
            result = cur.execute("SELECT * FROM users WHERE phone = %s", [search])
            if result < 1:
                result = cur.execute("SELECT * FROM users WHERE name = %s", [search])
                users = cur.fetchall()

                counter = 0

                for user in users:
                    if user['admin'] != 1:
                        counter += 1
                
                return render_template("dashboard.html", users=users, counter=counter)

            users = cur.fetchall()

            counter = 0

            for user in users:
                if user['admin'] != 1:
                    counter += 1

            return render_template("dashboard.html", users=users, counter=counter)



        val = request.form.getlist('access')

        cur = mysql.connection.cursor()

        for user in users:
            cur.execute("UPDATE users SET access = 0 WHERE id = %s", [user['id']])
            mysql.connection.commit()
        
        for i in val:
            cur.execute("UPDATE users SET access = 1 WHERE id = %s", [i])
            mysql.connection.commit()

    cur = mysql.connection.cursor()
    
    result = cur.execute("SELECT * FROM users")

    users = cur.fetchall()

    counter = 0

    for user in users:
         if user['admin'] != 1:
            counter += 1

    if result > 0:
        return render_template('dashboard.html', users=users, counter=counter)
    else:
        msg = 'No users yet.'
        return render_template('dashboard.html', msg=msg, counter=counter)
    # Close connection
    cur.close()


class ArticleForm(Form):
    title = StringField('Title', [validators.Length(min=1, max=200)])
    body = TextAreaField('Body', [validators.Length(min=30)])

# Add Article
@app.route('/add_article', methods=['GET', 'POST'])

def add_article():
    form = ArticleForm(request.form)
    if request.method == 'POST' and form.validate():
        title = form.title.data
        body = form.body.data

        # Create Cursor
        cur = mysql.connection.cursor()

        # Execute
        cur.execute("INSERT INTO articles(title, body, author) VALUES(%s, %s, %s)",(title, body, session['username']))

        # Commit to DB
        mysql.connection.commit()

        #Close connection
        cur.close()

        flash('Article Created', 'success')

        return redirect(url_for('dashboard'))

    return render_template('add_article.html', form=form)

@app.route("/set_test", methods=['GET', 'POST'])
@is_logged_in
def set_test():
    
    return render_template("set_test.html")



@app.route("/test_pre_A1", methods=['GET', 'POST'])
@got_once_pre_A1
@is_logged_inu
@passp
@notFall
def test_pre_A1():
    global h
    global d
    global dt_stringe
    marks = 0
    lm = 0
    rm = 0
    gm = 0
    fm = 0
    gm2 = 0

    cur = mysql.connection.cursor()

    if request.method == 'POST':
        
        p1Ans = ['A', 'C', 'E', 'G']
        p2Ans = ['B', 'C', 'A', 'B']
        p3Ans = ['A', 'A', 'C', 'A']
        p4Ans = ['B', 'A', 'B', 'C']
        p5Ans = ['B', 'A', 'A', 'C', 'B', 'C', 'A', 'C']

        

        val = request.form.getlist('listening')
        for i in range(len(val)):
            if val[i] in p1Ans:
                lm += 1 
                marks += 1
        
        if d == 0:
            cur.execute("UPDATE users SET lpre_a1 = %s WHERE id = %s", (str(lm) + '//4', session['id']['id']))
            mysql.connection.commit()
        
        for i in range(4):
            name = "reading" + str(i+1)
            val = request.form.get(name)
            if val == p2Ans[i]:
                rm += 1
                marks += 1
        
        if d == 0:
            cur.execute("UPDATE users SET rpre_a1 = %s WHERE id = %s", (str(rm) + '//4', session['id']['id']))
            mysql.connection.commit()

        for i in range(4):
            name = "grammar" + str(i+1)
            val = request.form.get(name)
            if val == p3Ans[i]:
                gm += 1
                marks += 1
        
        if d == 0:
            cur.execute("UPDATE users SET gpre_a1 = %s WHERE id = %s", (str(gm) + '//4', session['id']['id']))
            mysql.connection.commit()

        for i in range(4):
            name = "functional_language" + str(i+1)
            val = request.form.get(name)
            if val == p4Ans[i]:
                fm += 1
                marks += 1
        
        if d == 0:
            cur.execute("UPDATE users SET fpre_a1 = %s WHERE id = %s", (str(fm) + '//4', session['id']['id']))
            mysql.connection.commit()

        for i in range(8):
            name = "2grammar" + str(i+1)
            val = request.form.get(name)
            if val == p5Ans[i]:
                gm2 += 1
                marks += 1
        
        if d == 0:
            cur.execute("UPDATE users SET g2pre_a1 = %s WHERE id = %s", (str(gm2) + '//8', session['id']['id']))
            mysql.connection.commit()

        if d == 0:
            cur.execute("UPDATE users SET pre_a1 = %s WHERE id = %s", (str(marks) + '//24', session['id']['id']))
            mysql.connection.commit()
        
        if h > 1 and d == 1:
            cur.execute("INSERT INTO test%s_%s(lpre_a1, rpre_a1, gpre_a1, fpre_a1, g2pre_a1, pre_a1, date) VALUES(%s, %s, %s, %s, %s, %s, %s)", (h, session['id']['id'], str(lm) + '//4', str(rm) + '//4', str(gm) + '//4', str(fm) + '//4', str(gm2) + '//8', str(marks) + '//24', dt_stringe))
            mysql.connection.commit()

        cur.close()
        
        if marks >= 19:
            session['pass1'] = True
            return redirect(url_for("move_to_a1"))
       
        return redirect(url_for("fall"))
                
    session['started_pre_A1'] = True

    h = 0
    d = 0

    cur.execute("select * from users  WHERE id = %s", [session['id']['id']])
    t = cur.fetchone()
    for i in range(2, 10000):
        try:
            cur.execute("select * from test%s_%s",( i, session['id']['id']))
            n = cur.fetchone()
        except Exception:
            h = i
            break
    
    if t['lpre_a1']:
        d = 1
        cur.execute("""CREATE TABLE test%s_%s (
        lpre_a1 VARCHAR(100), rpre_a1 VARCHAR(100), gpre_a1 VARCHAR(100), fpre_a1 VARCHAR(100), g2pre_a1 VARCHAR(100), pre_a1 VARCHAR(100),
        la1 VARCHAR(100), ra1 VARCHAR(100), va1 VARCHAR(100), fa1 VARCHAR(100), ga1 VARCHAR(100), a1 VARCHAR(100),
        la2 VARCHAR(100), ra2 VARCHAR(100), va2 VARCHAR(100), fa2 VARCHAR(100), ga2 VARCHAR(100), a2 VARCHAR(100),
        lb1 VARCHAR(100), rb1 VARCHAR(100), phb1 VARCHAR(100), fb1 VARCHAR(100), gb1 VARCHAR(100), b1 VARCHAR(100),
        lb2 VARCHAR(100), rb2 VARCHAR(100), vb2 VARCHAR(100), fb2 VARCHAR(100), gb2 VARCHAR(100), b2 VARCHAR(100),
        date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )""", (h, session['id']['id']))
        mysql.connection.commit()

        nowe = datetime.datetime.now()
        dt_stringe = nowe.strftime("%Y-%m-%d %H:%M:%S")
    else:
        
        now = datetime.datetime.now()
        dt_string = now.strftime("%Y-%m-%d %H:%M:%S")

        cur.execute("UPDATE users SET date = %s WHERE id = %s", [dt_string, session['id']['id']])
        mysql.connection.commit()

    return render_template("test_pre_A1.html")



@app.route("/test_A1", methods=['GET', 'POST'])
@got_once_A1
@is_logged_inu
@pass1
@notFall
def test_A1():
    global h
    global d
    global ort
    marks = 0
    lm = 0
    rm = 0
    vm = 0
    fm = 0
    gm = 0

    cur = mysql.connection.cursor()

    if request.method == 'POST':
        p1Ans = ['A', 'D', 'B', 'B']
        p2Ans = ['D', 'D', 'D', 'C']
        p3Ans = ['D', 'B', 'C', 'C']
        p4Ans = ['A', 'C', 'C', 'A']
        p5Ans = ['B', 'D', 'A', 'C', 'D', 'B', 'A', 'C']

        for i in range(4):
            name = "listening" + str(i+1)
            val = request.form.get(name)
            if val == p1Ans[i]:
                lm += 1
                marks += 1
        if d == 0:
            cur.execute("UPDATE users SET la1 = %s WHERE id = %s", (str(lm) + '//4', session['id']['id']))
            mysql.connection.commit()

        for i in range(4):
            name = "reading" + str(i+1)
            val = request.form.get(name)
            if val == p2Ans[i]:
                rm += 1
                marks += 1
        if d == 0:
            cur.execute("UPDATE users SET ra1 = %s WHERE id = %s", (str(rm) + '//4', session['id']['id']))
            mysql.connection.commit()

        for i in range(4):
            name = "vocabulary" + str(i+1)
            val = request.form.get(name)
            if val == p3Ans[i]:
                vm += 1
                marks += 1
        if d == 0:
            cur.execute("UPDATE users SET va1 = %s WHERE id = %s", (str(vm) + '//4', session['id']['id']))
            mysql.connection.commit()

        for i in range(4):
            name = "functional_language" + str(i+1)
            val = request.form.get(name)
            if val == p4Ans[i]:
                fm += 1
                marks += 1
        if d == 0:
            cur.execute("UPDATE users SET fa1 = %s WHERE id = %s", (str(fm) + '//4', session['id']['id']))
            mysql.connection.commit()

        for i in range(8):
            name = "grammar" + str(i+1)
            val = request.form.get(name)
            if val == p5Ans[i]:
                gm += 1
                marks += 1
        if d == 0:
            cur.execute("UPDATE users SET ga1 = %s WHERE id = %s", (str(gm) + '//8', session['id']['id']))
            mysql.connection.commit()

        if d == 0:
            cur.execute("UPDATE users SET a1 = %s WHERE id = %s", (str(marks) + '//24', session['id']['id']))
            mysql.connection.commit()


        if ort == 1:
            cur.execute("UPDATE test%s_%s SET la1 = %s, ra1 = %s, va1 = %s, fa1 = %s, ga1 = %s, a1 = %s", (h, session['id']['id'], str(lm) + '//4', str(rm) + '//4', str(vm) + '//4', str(fm) + '//4', str(gm) + '//8', str(marks) + '//24'))
            mysql.connection.commit()


        elif d == 1:
            cur.execute("UPDATE test%s_%s SET la1 = %s, ra1 = %s, va1 = %s, fa1 = %s, ga1 = %s, a1 = %s", (h, session['id']['id'], str(lm) + '//4', str(rm) + '//4', str(vm) + '//4', str(fm) + '//4', str(gm) + '//8', str(marks) + '//24'))
            mysql.connection.commit()
        # UPDATE table-name SET column-name = value, column-name = value

        cur.close()
        
        if marks >= 19:
            session['pass2'] = True
            return redirect(url_for("move_to_a2"))
       
        return redirect(url_for("fall"))

    session['finished_pre_A1'] = True
    return render_template("test_A1.html")



@app.route("/test_A2", methods=['GET', 'POST'])
@got_once_A2
@is_logged_inu
@pass2
@notFall
def test_A2():
    global h
    global d
    marks = 0
    lm = 0
    rm = 0
    vm = 0
    fm = 0
    gm = 0

    cur = mysql.connection.cursor()

    if request.method == 'POST':
        p1Ans = ['B', 'D', 'G', 'J']
        p2Ans = ['D', 'C', 'B', 'D']
        p3Ans = ['A', 'C', 'A', 'C']
        p4Ans = ['A', 'D', 'B', 'C']
        p5Ans = ['A', 'D', 'B', 'C', 'A', 'A', 'A', 'A']

        val = request.form.getlist('listening')
        for i in range(len(val)):
            if val[i] in p1Ans:
                lm += 1
                marks += 1
        
        if d == 0:
            cur.execute("UPDATE users SET la2 = %s WHERE id = %s", (str(lm) + '//4', session['id']['id']))
            mysql.connection.commit()


        for i in range(4):
            name = "reading" + str(i+1)
            val = request.form.get(name)
            if val == p2Ans[i]:
                rm += 1
                marks += 1

        if d == 0:
            cur.execute("UPDATE users SET ra2 = %s WHERE id = %s", (str(rm) + '//4', session['id']['id']))
            mysql.connection.commit()

        for i in range(4):
            name = "vocabulary" + str(i+1)
            val = request.form.get(name)
            if val == p3Ans[i]:
                vm += 1
                marks += 1

        if d == 0:
            cur.execute("UPDATE users SET va2 = %s WHERE id = %s", (str(vm) + '//4', session['id']['id']))
            mysql.connection.commit()

        for i in range(4):
            name = "functional_language" + str(i+1)
            val = request.form.get(name)
            if val == p4Ans[i]:
                fm += 1
                marks += 1

        if d == 0:
            cur.execute("UPDATE users SET fa2 = %s WHERE id = %s", (str(fm) + '//4', session['id']['id']))
            mysql.connection.commit()

        for i in range(8):
            name = "grammar" + str(i+1)
            val = request.form.get(name)
            if val == p5Ans[i]:
                gm += 1
                marks += 1

        if d == 0:
            cur.execute("UPDATE users SET ga2 = %s WHERE id = %s", (str(gm) + '//8', session['id']['id']))
            mysql.connection.commit()

        if d == 0:
            cur.execute("UPDATE users SET a2 = %s WHERE id = %s", (str(marks) + '//24', session['id']['id']))
            mysql.connection.commit()

        if h > 1 and d == 1:
            cur.execute("UPDATE test%s_%s SET la2 = %s, ra2 = %s, va2 = %s, fa2 = %s, ga2 = %s, a2 = %s", (h, session['id']['id'], str(lm) + '//4', str(rm) + '//4', str(vm) + '//4', str(fm) + '//4', str(gm) + '//8', str(marks) + '//24'))
            mysql.connection.commit()

        cur.close()
        
        if marks >= 19:
            session['pass3'] = True
            return redirect(url_for("move_to_b1"))
       
        return redirect(url_for("fall"))

    session['finished_A1'] = True
    return render_template("test_A2.html")



@app.route("/test_B1", methods=['GET', 'POST'])
@got_once_B1
@is_logged_inu
@pass3
@notFall
def test_B1():
    global h
    global d
    marks = 0
    lm = 0
    rm = 0
    phm = 0
    fm = 0
    gm = 0

    cur = mysql.connection.cursor()

    if request.method == 'POST':
        p1Ans = ['A', 'C', 'D', 'G']
        p2Ans = ['A', 'B', 'C', 'B']
        p3Ans = ['C', 'B', 'A', 'B']
        p4Ans = ['C', 'C', 'B', 'A']
        p5Ans = ['A', 'B', 'B', 'B', 'B', 'B', 'A', 'A']

        val = request.form.getlist('listening')
        for i in range(len(val)):
            if val[i] in p1Ans:
                lm += 1
                marks += 1

        if d == 0:
            cur.execute("UPDATE users SET lb1 = %s WHERE id = %s", (str(lm) + '//4', session['id']['id']))
            mysql.connection.commit()

        for i in range(4):
            name = "reading" + str(i+1)
            val = request.form.get(name)
            if val == p2Ans[i]:
                rm += 1
                marks += 1
        
        if d == 0:
            cur.execute("UPDATE users SET rb1 = %s WHERE id = %s", (str(rm) + '//4', session['id']['id']))
            mysql.connection.commit()

        for i in range(4):
            name = "phonetics" + str(i+1)
            val = request.form.get(name)
            if val == p3Ans[i]:
                phm += 1
                marks += 1

        if d == 0:
            cur.execute("UPDATE users SET phb1 = %s WHERE id = %s", (str(phm) + '//4', session['id']['id']))
            mysql.connection.commit()

        for i in range(4):
            name = "functional_language" + str(i+1)
            val = request.form.get(name)
            if val == p4Ans[i]:
                fm += 1
                marks += 1

        if d == 0:
            cur.execute("UPDATE users SET fb1 = %s WHERE id = %s", (str(fm) + '//4', session['id']['id']))
            mysql.connection.commit()

        for i in range(8):
            name = "grammar" + str(i+1)
            val = request.form.get(name)
            if val == p5Ans[i]:
                gm += 1
                marks += 1

        if d == 0:
            cur.execute("UPDATE users SET gb1 = %s WHERE id = %s", (str(gm) + '//8', session['id']['id']))
            mysql.connection.commit()
        
        if d == 0:
            cur.execute("UPDATE users SET b1 = %s WHERE id = %s", (str(marks) + '//24', session['id']['id']))
            mysql.connection.commit()

        if h > 1 and d == 1:
            cur.execute("UPDATE test%s_%s SET lb1 = %s, rb1 = %s, phb1 = %s, fb1 = %s, gb1 = %s, b1 = %s", (h, session['id']['id'], str(lm) + '//4', str(rm) + '//4', str(phm) + '//4', str(fm) + '//4', str(gm) + '//8', str(marks) + '//24'))
            mysql.connection.commit()

        cur.close()

        if marks >= 19:
            session['pass4'] = True
            return redirect(url_for("move_to_b2"))
       
        return redirect(url_for("fall"))

    session['finished_A2'] = True
    return render_template("test_B1.html")



@app.route("/test_B2", methods=['GET', 'POST'])
@got_once_B2
@is_logged_inu
@pass4
@notFall
def test_B2():
    global h
    global d
    marks = 0
    lm = 0
    rm = 0
    vm = 0
    fm = 0
    gm = 0

    cur = mysql.connection.cursor()

    if request.method == 'POST':
        p1Ans = ['A', 'C', 'G', 'H']
        p2Ans = ['A', 'C', 'E', 'F']
        p3Ans = ['A', 'B', 'C', 'A']
        p4Ans = ['B', 'A', 'A', 'A']
        p5Ans = ['A', 'A', 'B', 'A', 'A', 'A', 'B', 'A']

        val = request.form.getlist('listening')
        for i in range(len(val)):
            if val[i] in p1Ans:
                lm += 1
                marks += 1

        if d == 0:
            cur.execute("UPDATE users SET lb2 = %s WHERE id = %s", (str(lm) + '//4', session['id']['id']))
            mysql.connection.commit()

        val = request.form.getlist('reading')
        for i in range(len(val)):
            if val[i] in p2Ans:
                rm += 1
                marks += 1

        if d == 0:
            cur.execute("UPDATE users SET rb2 = %s WHERE id = %s", (str(rm) + '//4', session['id']['id']))
            mysql.connection.commit()

        for i in range(4):
            name = "vocabulary" + str(i+1)
            val = request.form.get(name)
            if val == p3Ans[i]:
                vm += 1
                marks += 1

        if d == 0:
            cur.execute("UPDATE users SET vb2 = %s WHERE id = %s", (str(vm) + '//4', session['id']['id']))
            mysql.connection.commit()

        for i in range(4):
            name = "functional_language" + str(i+1)
            val = request.form.get(name)
            if val == p4Ans[i]:
                fm += 1
                marks += 1

        if d == 0:
            cur.execute("UPDATE users SET fb2 = %s WHERE id = %s", (str(fm) + '//4', session['id']['id']))
            mysql.connection.commit()

        for i in range(8):
            name = "grammar" + str(i+1)
            val = request.form.get(name)
            if val == p5Ans[i]:
                gm += 1
                marks += 1

        if d == 0:
            cur.execute("UPDATE users SET gb2 = %s WHERE id = %s", (str(gm) + '//8', session['id']['id']))
            mysql.connection.commit()
        
        if d == 0:
            cur.execute("UPDATE users SET b2 = %s WHERE id = %s", (str(marks) + '//24', session['id']['id']))
            mysql.connection.commit()

        if h > 1 and d == 1:
            cur.execute("UPDATE test%s_%s SET lb2 = %s, rb2 = %s, vb2 = %s, fb2 = %s, gb2 = %s, b2 = %s", (h, session['id']['id'], str(lm) + '//4', str(rm) + '//4', str(vm) + '//4', str(fm) + '//4', str(gm) + '//8', str(marks) + '//24'))
            mysql.connection.commit()

        cur.close()

        if marks >= 19:
            session['passAll'] = True
            return redirect(url_for("fall"))
       
        return redirect(url_for("fall"))

    session['finished_B1'] = True
    return render_template("test_B2.html")

@app.route("/test_result")
@is_logged_inu
def fall():
    global h
    session['fall'] = True

    cur = mysql.connection.cursor()

    cur.execute("UPDATE users SET access = 0 WHERE id = %s", [session['id']['id']])
    mysql.connection.commit()
    
    result = cur.execute("SELECT * FROM users WHERE id = %s", [session['id']['id']])

    user = cur.fetchone()
    
    tests = []
    for i in range(2, 10000):
        try:
            cur.execute("SELECT * FROM test%s_%s", (i, session['id']['id']))
            test = cur.fetchone()
            tests.append(test)
        except Exception:
            break

    tests.reverse()


    logout()
    
    return render_template('fall.html', user=user, tests=tests)
     
    
    cur.close()

@app.route('/test_result/<string:idd>/')
@is_logged_in
def test_result(idd):

    cur = mysql.connection.cursor()
    
    result = cur.execute("SELECT * FROM users WHERE id = %s", [idd])

    user = cur.fetchone()

    id = int(idd)

    tests = []
    for i in range(2, 10000):
        try:
            cur.execute("SELECT * FROM test%s_%s", (i, id))
            test = cur.fetchone()
            tests.append(test)
        except Exception:
            break

    tests.reverse()

    return render_template('fall.html', user=user, tests=tests, admin = '1')

    cur.close()

@app.route('/delet/<string:idd>/')
@is_logged_in
def delet(idd):
    cur = mysql.connection.cursor()
    
    cur.execute("DELETE FROM users WHERE id = %s", [idd])
    mysql.connection.commit()

    return redirect(url_for('dashboard'))


@app.route("/start_the_test", methods=['GET', 'POST'])
@is_logged_inu
@m
def move_to_pre_a1():
    if request.method == 'POST':
        return redirect(url_for("test_pre_A1"))
    return render_template("moving_forward.html", text="Would you like to start Pre A1 test?", start="Start")

@app.route("/move_to_a1", methods=['GET', 'POST'])
@is_logged_inu
@m1
def move_to_a1():
    if request.method == 'POST':
        return redirect(url_for("test_A1"))
    return render_template("moving_forward.html", text="Would you like to go to A1 test?")

@app.route("/move_to_a2", methods=['GET', 'POST'])
@is_logged_inu
@m2
def move_to_a2():
    if request.method == 'POST':
        return redirect(url_for("test_A2"))
    return render_template("moving_forward.html", text="Would you like to go to A2 test?")

@app.route("/move_to_b1", methods=['GET', 'POST'])
@is_logged_inu
@m3
def move_to_b1():
    if request.method == 'POST':
        return redirect(url_for("test_B1"))
    return render_template("moving_forward.html", text="Would you like to go to B1 test?")

@app.route("/move_to_b2", methods=['GET', 'POST'])
@is_logged_inu
@m4
def move_to_b2():
    if request.method == 'POST':
        return redirect(url_for("test_B2"))
    return render_template("moving_forward.html", text="Would you like to go to B2 test?")

    

@app.route("/download_users", methods=['GET', 'POST'])
@is_logged_in
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
                        cur.execute("select * from test%s_%s",( i, row['id']))
                        n = cur.fetchall()
                        print(n, i, row['id'])

                    except Exception:
                        break
                        print(n, i, row['id'])


                if n != ():
                    thewriter.writerow([
                        row['id'], row['name'], row['phone'], row['email'], n[0]['date'],
                        n[0]['lpre_a1'], n[0]['rpre_a1'], n[0]['gpre_a1'], n[0]['fpre_a1'], n[0]['g2pre_a1'], n[0]['pre_a1'],
                        n[0]['la1'], n[0]['ra1'], n[0]['va1'], n[0]['fa1'], n[0]['ga1'], n[0]['a1'],
                        n[0]['la2'], n[0]['ra2'], n[0]['va2'], n[0]['fa2'], n[0]['ga2'], n[0]['a2'],
                        n[0]['lb1'], n[0]['rb1'], n[0]['phb1'], n[0]['fb1'], n[0]['gb1'], n[0]['b1'], 
                        n[0]['lb2'], n[0]['rb2'], n[0]['vb2'], n[0]['fb2'], n[0]['gb2'], n[0]['b2']
                        ])
                else:
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

    


@app.route("/admin_login", methods=['GET', 'POST'])
def admin_login():
    if request.method == 'POST':
        phone = str(request.form['phone'])
        password = str(request.form['password'])


        cur = mysql.connection.cursor()
        result = cur.execute("SELECT * FROM users WHERE phone = %s AND admin = %b", [phone, 1])

        if result > 0:
            data = cur.fetchone()
            password_crypty = data['password']
            result1 = sha256_crypt.verify(password, password_crypty)

            if result1:
                session['logged_in'] = True
                session['admin_phone'] = phone
                session['admin_row'] = data
                return redirect(url_for('dashboard'))

        
        return render_template("admin_login.html", error='Invalid login')
    logout()
    return render_template("admin_login.html")


@app.route('/p_pre_a1/<string:idd>/')
@is_logged_in
def p_pre_a1(idd):
    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM users WHERE id = %s", [idd])
    user = cur.fetchone()
    
    if user['p_pre_a1'] == 0:
        cur.execute("UPDATE users SET p_pre_a1 = 1 WHERE id = %s", [idd])
        mysql.connection.commit()
    else :
        cur.execute("UPDATE users SET p_pre_a1 = 0 WHERE id = %s", [idd])
        mysql.connection.commit()

    cur.close()

    return redirect(url_for('test_result', idd = user['id']))

@app.route('/p_a1/<string:idd>/')
@is_logged_in
def p_a1(idd):
    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM users WHERE id = %s", [idd])
    user = cur.fetchone()
    
    if user['p_a1'] == 0:
        cur.execute("UPDATE users SET p_a1 = 1 WHERE id = %s", [idd])
        mysql.connection.commit()
    else :
        cur.execute("UPDATE users SET p_a1 = 0 WHERE id = %s", [idd])
        mysql.connection.commit()

    cur.close()

    return redirect(url_for('test_result', idd = user['id']))

@app.route('/p_a2/<string:idd>/')
@is_logged_in
def p_a2(idd):
    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM users WHERE id = %s", [idd])
    user = cur.fetchone()
    
    if user['p_a2'] == 0:
        cur.execute("UPDATE users SET p_a2 = 1 WHERE id = %s", [idd])
        mysql.connection.commit()
    else :
        cur.execute("UPDATE users SET p_a2 = 0 WHERE id = %s", [idd])
        mysql.connection.commit()
    
    cur.close()

    return redirect(url_for('test_result', idd = user['id']))

@app.route('/p_b1/<string:idd>/')
@is_logged_in
def p_b1(idd):
    cur = mysql.connection.cursor()

    cur.execute("SELECT * FROM users WHERE id = %s", [idd])
    user = cur.fetchone()
    
    if user['p_b1'] == 0:
        cur.execute("UPDATE users SET p_b1 = 1 WHERE id = %s", [idd])
        mysql.connection.commit()
    else :
        cur.execute("UPDATE users SET p_b1 = 0 WHERE id = %s", [idd])
        mysql.connection.commit()
    cur.close()

    return redirect(url_for('test_result', idd = user['id']))


@app.route('/reset_password/<string:idd>/', methods=['GET', 'POST'])
@is_logged_in
def rest_password(idd):
    if request.method == 'POST':
        password = request.form['password']
        confirm = request.form['confirm']
        if password == confirm: 
            password = sha256_crypt.encrypt(str(password))
            cur = mysql.connection.cursor()
            cur.execute("UPDATE users SET password = %s WHERE id = %s", (password, idd))
            mysql.connection.commit()

            return redirect(url_for('dashboard'))
        else: 
            return render_template('reset_password.html', error = "Passwords didn't mach. Try again")
        
    return render_template('reset_password.html')

    




    








    



    




if __name__ == '__main__':
    app.secret_key='secret123'
    app.run(debug=True)