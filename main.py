# IMPORTS
from flask import Flask, request, redirect, render_template, url_for, flash, session
from secrets import token_hex
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta, datetime, date
import bcrypt
from random import randint
from mails import mail as Email
from blueprints.admin import app as adminBlueprint
from dbmodels import app, db, Financial_Aid, User

# INITIATIONS AND CONFIGS
app.register_blueprint(adminBlueprint)
app.secret_key = token_hex(16)
app.permanent_session_lifetime = timedelta(hours=1)

# Educational Levels
educational_levels = {
    1: "Grade 9",
    2: "NCV(2)",
    3: "NCV(3)",
    4: "NCV(4)",
    5: "Higher Certification",
    6: "Diploma Certification",
    7: "Degree Certification",
    7: "Honors Certification",
    8: "Masters Certification",
    9: "Doctors/ PhD Certification"
}

# automatically delete closed offers from the database
def update_database():
    financial_aids = Financial_Aid.query.all()
    for aid in financial_aids:
        if aid.closing_date < date.today():
            db.session.delete(aid)
            db.session.commit()

def popup(message, message_type):
    session['message'] = (message, message_type)
    session['message-sent'] = False


@app.route('/')
@app.route('/home')
@app.route('/index-page')
def index_page():
    if session.get('username'):
        if not session.get("message-sent"):
            session['message-sent'] = True
            return render_template('index-page.html', message=session.get('message'), username=session.get('username'))
        else:
            return render_template('index-page.html', message=(None, None), username=session.get('username'))
    else:
        return redirect(url_for('login'))

@app.route('/scholarships')
def scholarships():
    res = Financial_Aid.query.all()
    for aid in res:
        aid.closing_date =  aid.closing_date.strftime( "%d %B, %Y" )
        aid.days_left = (aid.opening_date-date.today()).days
        aid.opening_date =  aid.opening_date.strftime( "%d %B, %Y" )
    if "username" in session:
        return render_template('scholarships.html', data=res, username=session['username'],
            message=(None, None))
    else:
        return redirect(url_for('login'))
    
@app.route('/bursaries')
def bursaries():
    res = Financial_Aid.query.all()
    for aid in res:
        aid.closing_date =  aid.closing_date.strftime( "%d %B, %Y" )
        aid.days_left = (aid.opening_date-date.today()).days
        aid.opening_date =  aid.opening_date.strftime( "%d %B, %Y" )
    if "username" in session:
        return render_template('bursaries.html', data=res, username=session['username'],
            message=(None, None))
    else:
        return redirect(url_for('login'))
    
@app.route('/grants')
def grants():
    res = Financial_Aid.query.all()
    for aid in res:
        aid.closing_date =  aid.closing_date.strftime( "%d %B, %Y" )
        aid.days_left = (aid.opening_date-date.today()).days
        aid.opening_date =  aid.opening_date.strftime( "%d %B, %Y" )
    if "username" in session:
        return render_template('grants.html', data=res, username=session['username'],
            message=(None, None))
    else:
        return redirect(url_for('login'))
    
@app.route('/view_aid<id>')
def view_aid(id):
    res =  Financial_Aid.query.filter_by(_id=int(id)).first()
    res.supported_fields = [field for field in res.supported_fields.split('-') if field != ""]
    res.requirements_list = [req for req in res.requirements_list.split('-') if req != ""]
    return render_template('aid_info.html', financial_aid=res, message=(None, None))


# SIGNUP
@app.route('/signup', methods=['GET','POST'])
def signup():
    if request.method == 'POST':
        fname = request.form['fname']
        lname = request.form['lname']
        phone_num = request.form['phone-number']
        email = request.form['email-address']
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm-password']

        for user in User.query.all():
            if user.email_address == email.lower():
                return render_template('signup.html', error="email address already registered!", message=(None, None))

        if password != confirm_password:
            return render_template('signup.html', error="Password doesn't match!", message=(None, None))

        if len(password) < 6:
            return render_template('signup.html', error="password must contain at least 6 characters", message=(None, None))
        new_user = User(first_name=fname, last_name=lname
                        , email_address=email,
                        phone_number=phone_num, username=username, password=password)
        db.session.add(new_user)
        db.session.commit()
        email
        popup("Account created successfully!", "success")
        Email.send_welcome_message(new_user.email_address, new_user.username, "https://localhost:5000/")
        return redirect(url_for('login'))
    else:
        session['message'] = (None, None)
        return render_template('signup.html',
            message=session.get('message'),
            educational_levels=educational_levels)

# LOGIN
@app.route('/login', methods=['GET','POST'])
def login():
    if  request.method == 'POST':
        username_email_address = request.form['username-email-address'].strip()
        password = request.form['password'].strip()
        user = User.query.filter_by(username=username_email_address).first()
        user1 = User.query.filter_by(email_address=username_email_address).first()

        print(user, user1, username_email_address, password)
        # Admin login
        if username_email_address == "CoolAsCode@2024!Admin" and  password == "CoolAsCode@2024!":
            popup("Welcome Back Admin!", "success")
            session.permanent = True
            session['admin-access'] = True
            return redirect(url_for("admin.index"))
        # User login
        if user and bcrypt.checkpw(password.encode('utf-8'), user.password):
            session.permanent = True
            session['username'] = user.username
            session['user'] = user._id
            popup(f"Welcome Back {session.get('username')}", "success")
            return redirect(url_for('index_page'))
        elif user1 and bcrypt.checkpw(password.encode('utf-8'), user1.password):
            session.permanent = True
            session['username'] = user1.username
            session['user'] = user._id
            popup(f"Welcome Back {session.get('username')}", "success")
            return redirect(url_for('index_page'))
        else:
            return render_template("login.html", error="Invalid username or password", message=(None, None))
    else:
        if "username" not in session:
            if session.get('message-sent'):
                return render_template('login.html', 
                    message=(None, None))
            else:
                session['message-sent'] = True
                return render_template('login.html', 
                    message=session.get("message"))
        else:
            return redirect(url_for('index_page'))

@app.route('/logout')
def logout():
    if 'username' in session:
        session.pop('username', None)
        session['admin-access'] = False
        session.permanent = False
        popup("Thanks for your service :)!","info")
    return redirect(url_for('login'))


@app.route('/recover_password', methods=['GET', 'POST'])
def recover_password():
    if  request.method == 'POST':
        email = request.form['email']
        user = User.query.filter_by(email_address=email).first()
        if user:
            session['passcode'] = token_hex(4).upper()
            session['requestor-email'] = user.email_address
            msg = f"Enter the code: {session.get('passcode')} to verify you are changing your password!"
            Email.send_email(user.email_address, "Password Code Verification", msg)
            return redirect(url_for('confirm_passcode'))
        else:
            return render_template('recover_password.html', error="Invalid email address")
    else:   
        return render_template('recover_password.html')

@app.route('/confirm_passcode', methods=['GET', 'POST'])
def confirm_passcode():
    if request.method == 'POST':
        passcode = request.form['passcode']

        if passcode == session.get('passcode'):
            user = User.query.filter_by(email_address=session.get('requestor-email')).first()
            random_password = randint(100000, 999999)
            Email.send_email(session.get('requestor-email'), "Password Sent!", f"Your temporary password for your account is {random_password}.. Don't share this with anyone")
            user.password = bcrypt.hashpw(str(random_password).encode('utf-8'), bcrypt.gensalt())
            db.session.commit()
            return redirect(url_for('login'))
        return render_template('confirm_passcode.html', error="Invalid Passcode")
    else:
        return render_template('confirm_passcode.html')


@app.route('/startup')
def startup():
    return render_template('startup.html')

@app.route('/search', methods=['GET', 'POST'])
def search():
    if  request.method=='POST':
        results = []
        keyword = request.form['search']
        
        searchField = request.form['search']
        all_financial_aids = Financial_Aid.query.all()

        for  aid in all_financial_aids:
            fields = [field for field in aid.supported_fields.split('-') if field != '']
            for field in fields:
                if field.strip().lower() == searchField.strip().lower():
                    results.append(aid)
            if aid.name.strip().lower() == searchField.strip().lower() and \
            aid not in results:
                results.append(aid)

        return render_template('show_results.html', results=results, number_of_results=len(results), keyword=keyword,
                username=session['username'], message=(None, None))

@app.route('/help/password_recovery')
def help_suggestion():
    return render_template('password_recovery_suggestion.html')

@app.route('/demo_profile')
def  demo_profile():
    return render_template('demo_profile.html')

@app.route('/user/my_profile')
def my_profile():
    if session.get('username'):
        user = User.query.filter_by(_id=int(session.get('user'))).first()
        return render_template('my_profile.html', user=user)
    else:
        return redirect(url_for('index_page'))
    
@app.route('/user/edit_user_profile/<id>', methods=['GET', 'POST'])
def  edit_user_profile(id):
    if request.method == 'POST':
        user =  User.query.filter_by(_id=int(id)).first()
        user.first_name = request.form['fname']
        user.last_name = request.form['lname']
        user.phone_number = request.form['phone-number']
        user.email_address = request.form['email-address']
        user.username = request.form['username']

        db.session.commit()
        session['username'] = user.username
        popup('Profile updated successfully!','info')
        return redirect(url_for('index_page'))
    else:
        if session.get('username'):
            user = User.query.filter_by(_id=id).first()
            return render_template('edit_user_profile.html', user=user)
        else:
            return redirect(url_for('index_page'))
    

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5000, debug=True)

