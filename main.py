# IMPORTS
from flask import Flask, request, redirect, render_template, url_for, flash, session
from secrets import token_hex
from flask_sqlalchemy import SQLAlchemy
from datetime import timedelta, datetime, date
import bcrypt
from random import randint
from sqlalchemy.exc import IntegrityError
from mails import mail as Email


# INITIATIONS AND CONFIGS
app = Flask(__name__)
app.secret_key = token_hex(16)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"  # Use
app.permanent_session_lifetime = timedelta(hours=1)
db = SQLAlchemy(app)

# FINANCIAL AID MODEL
class Financial_Aid(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    _type = db.Column(db.String(20), nullable=False)
    opening_date = db.Column(db.Date)
    closing_date = db.Column(db.Date)
    supported_fields = db.Column(db.String(250), nullable=False)
    requirements_list = db.Column(db.String(250), nullable=False)
    url_link =  db.Column(db.String(150))
    email_address = db.Column(db.String(50))
    status = db.Column(db.String(30), nullable=False, default= "Open")

    def __init__(self, name, _type, closing_date, supported_fields, requirements_list, 
        url_link, opening_date, email_address) -> None:
        self.name = name
        self._type = _type
        self.opening_date = opening_date
        self.closing_date = closing_date
        self.supported_fields = supported_fields
        self.requirements_list = requirements_list
        self.url_link = url_link
        self.status = self.get_status()
        self.email_address = email_address
        
    def get_status(self):
        if date.today() > self.closing_date:
            return  "Closed"
        elif self.opening_date <= date.today() <= self.closing_date:
            return "Open for Applications"
        elif date.today() < self.opening_date:
            return  "Not Open Yet"
        
# USER MODEL
class User(db.Model):
    _id = db.Column("id", db.Integer, primary_key=True)
    first_name = db.Column(db.String(50), nullable=False)
    last_name = db.Column(db.String(50), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    email_address = db.Column(db.String(50), nullable=False)
    username = db.Column(db.String(50), nullable=False)
    password = db.Column(db.String(50), nullable=False)

    def __init__(self, first_name, last_name, phone_number, email_address, username, password) -> None:
        self.first_name = first_name
        self.last_name = last_name
        self.phone_number = phone_number
        self.email_address = email_address
        self.username = username
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

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
    
@app.route('/view_aid/<id>')
def view_aid(id):
    res =  Financial_Aid.query.filter_by(_id=int(id)).first()
    res.supported_fields = [field for field in res.supported_fields.split('-') if field != ""]
    res.requirements_list = [req for req in res.requirements_list.split('-') if req != ""]
    return render_template('aid_info.html', financial_aid=res, message=(None, None))

# ADMIN
@app.route('/admin/')
@app.route('/admin/home')
def admin():
    users = User.query.all()
    aids = Financial_Aid.query.all()
    if session.get('admin-access'):
        if not session.get('message-sent'):
            session['message-sent'] = True
            return render_template('admin_index.html', 
            message=session.get('message'), number_of_users=len(users), 
            number_of_financial_aids=len(aids))
        else:
            return render_template('admin_index.html', 
            message=(None, None), number_of_users=len(users), 
            number_of_financial_aids=len(aids))
    else:
        return redirect(url_for('login'))

@app.route('/admin/create_aid', methods=[ 'GET','POST'])
def create_aid():

    if  request.method =='POST':
        name = request.form['financial-aid-name']
        _type = request.form['financial-aid-type']
        opening_date = datetime.strptime(request.form['opening-date'], '%Y-%m-%d').date()
        closing_date = datetime.strptime(request.form['closing-date'], '%Y-%m-%d').date()
        supported_fields = request.form['supported-fields']
        requirements_list = request.form['requirements-list']
        url_link = request.form['url-link']
        email_address = request.form['email-address']


        new_financial_aid = Financial_Aid(name=name, _type=_type, opening_date=opening_date,
            closing_date=closing_date, supported_fields=supported_fields, requirements_list=requirements_list,
            url_link=url_link, email_address=email_address)
        db.session.add(new_financial_aid)
        db.session.commit()
        # sending a message to all users
        users = User.query.all()
        for user in users:
            Email.send_new_financial_aid_update(user.email_address, user.username, new_financial_aid, "localhost:5000")
        popup("New Finacial Aid Added Sucessfully!", "success")
        return redirect(url_for('view_all'))
    else:
        if session.get('admin-access'):
            return render_template('create_aid.html', today=date.today())
        else:
            return redirect(url_for('login'))
        
@app.route('/admin/view_all')
def view_all():
    res = Financial_Aid.query.all()
    
    if session.get('admin-access'):
        if not session.get('message-sent'):
            session['message-sent'] = True
            return render_template('view_all.html', data=res, 
                message=session.get('message'))
        else:
            return render_template('view_all.html', data=res, 
                message=(None, None))
    else:
        return redirect(url_for('login'))



@app.route('/admin/read_aid/<id>')
def read_aid(id):
    res = Financial_Aid.query.filter_by(_id=int(id)).first()

    res.supported_fields = res.supported_fields.split('-')
    res.requirements_list = res.requirements_list.split('-')
    res.supported_fields = [field for field in res.supported_fields if field != ""]
    res.requiremets_list = [req for req in res.requirements_list if req != ""]
    return render_template('read_aid.html', financial_aid=res)

@app.route('/admin/update_aid/<id>', methods=['GET', 'POST'])
def update_aid(id):
    if  request.method=='POST':
        res = Financial_Aid.query.filter_by(_id=int(id)).first()
        res.name = request.form['financial-aid-name']
        res._type = request.form['financial-aid-type']
        res.opening_date = datetime.strptime(request.form['opening-date'], '%Y-%m-%d').date()
        res.closing_date = datetime.strptime(request.form['closing-date'], '%Y-%m-%d').date()
        res.supported_fields = request.form['supported-fields']
        res.requirements_list = request.form['requirements-list']
        res.url_link = request.form['url-link']
        res.email_address = request.form['email-address']

        db.session.commit()
        popup("Aid Updated Sucessfully", "success")
        return redirect(url_for('view_all'))
    else:
        res = Financial_Aid.query.filter_by(_id=int(id)).first()
        return render_template('update_aid.html', financial_aid=res)

@app.route('/admin/delete_aid/<id>', methods=["GET", "POST"])
def delete_aid(id):
    if request.method == 'POST':
        res =  Financial_Aid.query.filter_by(_id=int(id)).one()
        db.session.delete(res)
        db.session.commit()
        session['message'] = f"{{res.name}} Has Been Deleted Sucessfully!"
        session['message_type'] = "danger"
        
        return redirect(url_for("view_all"))
    else:
        res = Financial_Aid.query.filter_by(_id=int(id)).first()
        return render_template('delete_aid.html', financial_aid=res, method=request.method)


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
            message=session.get('message'))

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
            return redirect(url_for('admin'))
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

@app.route('/admin/view_all_users')
def view_all_users():
    res = User.query.all()
    if session.get('admin-access'):
        if session.get('message-sent'):
            return render_template('view_all_users.html', users=res,
                message=(None, None))
        else:
            session['message-sent'] = True
            return render_template('view_all_users.html', users=res,
                message=session.get('message'))
    else:
        return redirect(url_for('login'))
    
@app.route('/admin/create_user', methods=['GET','POST'])
def create_user():
    if session.get('admin-access'):
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
                    return render_template('create_user.html', error="email already exists")

            if password != confirm_password:
                return render_template('create_user.html', error="password doesn't match")

            new_user = User(first_name=fname, last_name=lname, phone_number=phone_num,
                            email_address=email, username=username, password=password)
            db.session.add(new_user)
            db.session.commit()
            popup('User Sucessfully Created!', 'success')
            return redirect(url_for('view_all_users'))
        else:
            return render_template('create_user.html')
    else:
        redirect(url_for('login'))

@app.route('/admin/read_user/<id>')
def read_user(id):
    res = User.query.filter_by(_id=int(id)).first()
    return render_template('read_user.html', user=res)

@app.route('/admin/update_user/<id>', methods=['GET', 'POST'])
def update_user(id):
    if  request.method == "POST":
        user =  User.query.filter_by(_id=int(id)).first()
        user.first_name = request.form['fname']
        user.last_name = request.form['lname']
        user.phone_number = request.form['phone-number']
        user.email_address = request.form['email-address']
        user.username = request.form['username']
        user.password = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())
        user.confirm_password = request.form['confirm-password']

        db.session.commit()
        popup("User Profile Updated Sucessfully!", "warning")
        return  redirect(url_for("view_all_users"))
    else:
        res = User.query.filter_by(_id=int(id)).first()
        return render_template('update_user.html', financial_aid=res)

@app.route('/admin/delete_user/<id>', methods=['GET', 'POST'])
def delete_user(id):
    if  request.method == "POST":
        user = User.query.filter_by(_id=int(id)).first()
        db.session.delete(user)
        db.session.commit()
        popup("User Sucessfully Deleted!", "danger")
        return   redirect(url_for("view_all_users"))
    else:
        res = User.query.filter_by(_id=int(id)).first()
        return render_template('delete_user.html', user=res)

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
    app.run(host="0.0.0.0", port=500)

