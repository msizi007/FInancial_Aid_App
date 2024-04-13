# IMPORTS
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from datetime import date
import bcrypt


# INITIATIONS AND CONFIGS
app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = "sqlite:///database.db"  # Use
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
