from flask import Blueprint, render_template, url_for, session, redirect, request
from mails import mail as Email
from datetime import datetime, date
from dbmodels import app, db, Financial_Aid, User

app = Blueprint("admin", __name__, url_prefix="/admin",\
    static_folder="static", template_folder="templates")


def popup(message, message_type):
    session['message'] = (message, message_type)
    session['message-sent'] = False


# ADMIN
@app.route('/')
@app.route('/dashboard')
def index():
    users = User.query.all()
    aids = Financial_Aid.query.all()
    if session.get('admin-access'):
        if not session.get('message-sent'):
            session['message-sent'] = True
            return render_template('index.html', 
            message=session.get('message'), number_of_users=len(users), 
            number_of_financial_aids=len(aids))
        else:
            return render_template('index.html', 
            message=(None, None), number_of_users=len(users), 
            number_of_financial_aids=len(aids))
    else:
        return redirect(url_for('login'))

@app.route('/create_aid', methods=[ 'GET','POST'])
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
        return redirect(url_for('view_financialAids'))
    else:
        if session.get('admin-access'):
            return render_template('create_aid.html', today=date.today())
        else:
            return redirect(url_for('login'))
        
@app.route('/view_financialAids')
def view_financialAids():
    res = Financial_Aid.query.all()
    
    if session.get('admin-access'):
        if not session.get('message-sent'):
            session['message-sent'] = True
            return render_template('view_financialAids.html', data=res, 
                message=session.get('message'))
        else:
            return render_template('view_financialAids.html', data=res, 
                message=(None, None))
    else:
        return redirect(url_for('login'))



@app.route('/read_aid/<id>')
def read_aid(id):
    print("Reading...")
    print('Started..')
    res = Financial_Aid.query.filter_by(_id=int(id)).first()
    print(res, res)
    res.supported_fields = res.supported_fields.split('-')
    res.requirements_list = res.requirements_list.split('-')
    res.supported_fields = [field for field in res.supported_fields if field != ""]
    res.requiremets_list = [req for req in res.requirements_list if req != ""]
    return render_template('read_aid.html', financial_aid=res)

@app.route('/update_aid/<id>', methods=['GET', 'POST'])
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
        return redirect(url_for('view_financialAids'))
    else:
        res = Financial_Aid.query.filter_by(_id=int(id)).first()
        return render_template('update_aid.html', financial_aid=res)

@app.route('/delete_aid/<id>', methods=["GET", "POST"])
def delete_aid(id):
    if request.method == 'POST':
        res =  Financial_Aid.query.filter_by(_id=int(id)).one()
        db.session.delete(res)
        db.session.commit()
        session['message'] = f"{{res.name}} Has Been Deleted Sucessfully!"
        session['message_type'] = "danger"
        
        return redirect(url_for("view_financialAids"))
    else:
        res = Financial_Aid.query.filter_by(_id=int(id)).first()
        return render_template('delete_aid.html', financial_aid=res, method=request.method)

@app.route('/view_all_users')
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


@app.route('/read_user/<id>')
def read_user(id):
    res = User.query.filter_by(_id=int(id)).first()
    return render_template('read_user.html', user=res)

