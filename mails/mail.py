import smtplib
from json import load

with open('mails/config.json') as json_file:
    data = load(json_file)

SENDER_EMAIL = data.get('email_address')
PASSWORD = data.get('password')

def send_email(receiver_email, subject, body):
    sever = smtplib.SMTP('smtp.gmail.com', 587)
    sever.starttls()
    sever.login(SENDER_EMAIL, PASSWORD)
    message = f'Subject: {subject}\n\n{body}'

    sever.sendmail(SENDER_EMAIL, receiver_email, message)
    sever.quit()

def send_welcome_message(receiver_email, username, link):
    sever = smtplib.SMTP('smtp.gmail.com', 587)
    sever.starttls()
    sever.login(SENDER_EMAIL, PASSWORD)
    subject = "Welcome Message!"

    with open('mails/welcome.txt') as welcome_txt:
        body = welcome_txt.read()
        body = body.replace('{{username}}', username)
    message = f'Subject: {subject}\n\n{body}'

    sever.sendmail(SENDER_EMAIL, receiver_email, message)
    sever.quit()

def send_closing_soon_message(receiver_email, financial_aid_name, link):
    sever = smtplib.SMTP('smtp.gmail.com', 587)
    sever.starttls()
    subject = f"{financial_aid_name} Closing Soon!"

    with open('mails/closing_soon.txt') as file:
        body = file.read()
        body = body.replace('{{financial_aid_name}}', financial_aid_name)
    sever.login(SENDER_EMAIL, PASSWORD)
    message = f'Subject: {subject}\n\n{body}'

    sever.sendmail(SENDER_EMAIL, receiver_email, message)
    sever.quit()

def send_new_financial_aid_update(receiver_email, username, financial_aid, link):
    sever = smtplib.SMTP('smtp.gmail.com', 587)
    sever.starttls()
    subject = f"New {financial_aid._type} Available!"

    with open('mails/new_aid_added.txt') as file:
        body = file.read()
        body = body.replace('{{financial_aid_name}}', financial_aid.name)
        body = body.replace('{{financial_aid_type}}', financial_aid._type)
        body = body.replace('{{username}}', username)
        body = body.replace('{{opening_date}}', str(financial_aid.opening_date))
        body = body.replace('{{closing_date}}', str(financial_aid.closing_date))
    sever.login(SENDER_EMAIL, PASSWORD)
    message = f'Subject: {subject}\n\n{body}'

    sever.sendmail(SENDER_EMAIL, receiver_email, message)
    sever.quit()