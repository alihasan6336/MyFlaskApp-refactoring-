# @app.route("/download_users", methods=['GET', 'POST'])
# def tt():
#     n = ()

#     # if request.method == 'POST':
#     cur = mysql.connection.cursor()

#     cur.execute("SELECT * FROM users")
#     allusers = cur.fetchall()

#     with open("file.csv", 'w', newline='') as f:
#         thewriter = csv.writer(f)
#         thewriter.writerow([
#             'id', 'name', 'phone', 'email', 'date', 
#             'Listening_Pre_A1', 'Reading_Pre_A1', 'Grammar_Pre_A1', 'Functional_language_Pre_A1', 'Grammar_Pre_A1', 'Pre_A1',
#             'listening_A1', 'Reading_A1', 'Vocabulary_A1', 'Functional_language_A1', 'Grammar_A1', 'A1', 
#             'listening_A2', 'Reading_A2', 'Vocabulary_A2', 'Functional_language_A2', 'Grammar_A2', 'A2', 
#             'listening_B1', 'Reading_B1', 'phonetics_B1', 'Functional_language_B1', 'Grammar_B1', 'B1', 
#             'listening_B2', 'Reading_B2', 'Vocabulary_B2', 'Functional_language_B2', 'Grammar_B2', 'B2', 
#             ])

#         for row in allusers:
#             n = ()
#             if row['admin'] == 0:
#                 for i in range(2, 10000):
#                     try:
#                         cur.execute("SELECT * FROM test%s_%s",( i, row['id']))
#                         n = cur.fetchall()
#                         #print(n, i, row['id'])

#                     except Exception:
#                         break
#                         #print(n, i, row['id'])


#                 if n != ():
#                     #print("got in if")
#                     thewriter.writerow([
#                         row['id'], row['name'], row['phone'], row['email'],  n[0]['date'],
#                         n[0]['lpre_a1'], n[0]['rpre_a1'], n[0]['gpre_a1'], n[0]['fpre_a1'], n[0]['g2pre_a1'], n[0]['pre_a1'],
#                         n[0]['la1'], n[0]['ra1'], n[0]['va1'], n[0]['fa1'], n[0]['ga1'], n[0]['a1'],
#                         n[0]['la2'], n[0]['ra2'], n[0]['va2'], n[0]['fa2'], n[0]['ga2'], n[0]['a2'],
#                         n[0]['lb1'], n[0]['rb1'], n[0]['phb1'], n[0]['fb1'], n[0]['gb1'], n[0]['b1'], 
#                         n[0]['lb2'], n[0]['rb2'], n[0]['vb2'], n[0]['fb2'], n[0]['gb2'], n[0]['b2']
#                         ])
#                 else:
#                     #print("got in else")
#                     thewriter.writerow([
#                         row['id'], row['name'], row['phone'], row['email'], str(row['date']),
#                         row['lpre_a1'], row['rpre_a1'], row['gpre_a1'], row['fpre_a1'], row['g2pre_a1'], row['pre_a1'],
#                         row['la1'], row['ra1'], row['va1'], row['fa1'], row['ga1'], row['a1'],
#                         row['la2'], row['ra2'], row['va2'], row['fa2'], row['ga2'], row['a2'],
#                         row['lb1'], row['rb1'], row['phb1'], row['fb1'], row['gb1'], row['b1'], 
#                         row['lb2'], row['rb2'], row['vb2'], row['fb2'], row['gb2'], row['b2']
#                         ])
                

#     return send_file('file.csv',
#     mimetype='text/csv',
#     cache_timeout=0,
#     attachment_filename='users.csv',
#     as_attachment=True)


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