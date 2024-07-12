from flask import Flask, render_template, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import requests
from datetime import datetime, timedelta, timezone
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from google.auth.transport.requests import Request
import os

app = Flask(__name__)

app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150))
    surname = db.Column(db.String(150))
    email = db.Column(db.String(150), unique=True)
    phone = db.Column(db.String(50))
    password = db.Column(db.String(150))

class Appointment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('appointments', lazy=True))
    date = db.Column(db.String(50), nullable=False)
    time = db.Column(db.String(50), nullable=False)
    hair_length = db.Column(db.String(50), nullable=False)
    hairstyle = db.Column(db.String(100), nullable=False)
    price = db.Column(db.String(50), nullable=False)
    event_id = db.Column(db.String(100), nullable=False)  # Dodaj ovu liniju

with app.app_context():
    db.create_all()



def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.route('/')
@login_required
def home():
    return render_template('main.html')

@app.route('/chat')
@login_required
def index():
    return render_template('chat.html')

@app.route('/schedule_form')
@login_required
def schedule_form():
    return render_template('schedule_form.html')

@app.route('/schedule', methods=['POST'])
@login_required
def schedule():
    try:
        name = request.form['name']
        date = request.form['date']
        time = request.form['time']
        hair_length = request.form['hair-length']
        hairstyle = request.form['hairstyle']
        price = request.form['price']

        start_time = datetime.strptime(f"{date} {time}", '%Y-%m-%d %H:%M')
        end_time = start_time + timedelta(hours=1)

        start_time_utc = start_time.replace(tzinfo=timezone.utc)
        end_time_utc = end_time.replace(tzinfo=timezone.utc)

        start_time_rfc3339 = start_time_utc.isoformat()
        end_time_rfc3339 = end_time_utc.isoformat()

        user_id = session['user_id']

        db_session = db.session
        user = db_session.get(User, user_id)

        creds = authenticate_google_calendar()
        service = build('calendar', 'v3', credentials=creds)
        
        events_result = service.events().list(
            calendarId='primary',
            timeMin=start_time_rfc3339,
            timeMax=end_time_rfc3339,
            singleEvents=True,
            orderBy='startTime'
        ).execute()
        
        events = events_result.get('items', [])
        
        if len(events) >= 2:
            return jsonify({'response': 'Termini za traženi vremenski interval su zauzeti.'}), 409

        event = {
            'summary': f'Zakazivanje - {name}',
            'description': f'Frizura: {hairstyle}, Dužina kose: {hair_length}, Cena: {price}\n\nKontakt:\n{user.name} {user.surname}\nTelefon: {user.phone}\nEmail: {user.email}',
            'start': {
                'dateTime': start_time_rfc3339,
                'timeZone': 'Europe/Belgrade',
            },
            'end': {
                'dateTime': end_time_rfc3339,
                'timeZone': 'Europe/Belgrade',
            },
            'attendees': [
                {'email': user.email},
            ],
        }

        created_event = service.events().insert(calendarId='primary', body=event).execute()
        event_id = created_event['id']

        new_appointment = Appointment(
            user_id=user.id,
            date=date,
            time=time,
            hair_length=hair_length,
            hairstyle=hairstyle,
            price=price,
            event_id=event_id
        )
        db_session.add(new_appointment)
        db_session.commit()

        response = f'Sve je uredu, zakazano je za {date} u {time}. Krajnje vreme je {end_time.strftime("%H:%M")}.'
        return jsonify({'response': response}), 200

    except Exception as e:
        print(f"Greška prilikom zakazivanja: {str(e)}")
        return jsonify({'response': 'Greška prilikom zakazivanja'}), 500

def authenticate_google_calendar():
    SCOPES = ['https://www.googleapis.com/auth/calendar']
    creds = None

    if os.path.exists('token.json') and os.path.getsize('token.json') > 0:
        creds = Credentials.from_authorized_user_file('token.json', SCOPES)
    else:
        flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
        creds = flow.run_local_server(port=8080)

        with open('token.json', 'w') as token:
            token.write(creds.to_json())

    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            flow = InstalledAppFlow.from_client_secrets_file('credentials.json', SCOPES)
            creds = flow.run_local_server(port=8080)

            with open('token.json', 'w') as token:
                token.write(creds.to_json())

    return creds

@app.route('/get_appointments', methods=['GET'])
@login_required
def get_appointments():
    try:
        user_id = session['user_id']
        appointments = Appointment.query.filter_by(user_id=user_id).all()
        appointments_data = [{
            'id': appointment.id,
            'date': appointment.date,
            'time': appointment.time,
            'hairstyle': appointment.hairstyle,
            'hair_length': appointment.hair_length,
            'price': appointment.price,
            'event_id': appointment.event_id
        } for appointment in appointments]
        
        return jsonify(appointments_data), 200

    except Exception as e:
        print(f"Greška prilikom dobijanja zakazivanja: {str(e)}")
        return jsonify({'response': 'Greška prilikom dobijanja zakazivanja.'}), 500
    

@app.route('/promeni_termin', methods=['GET', 'POST'])
@login_required
def promeni_termin():
    if request.method == 'POST':
        try:
            appointment_id = request.form['appointment_id']
            new_date = request.form['new_date']
            new_time = request.form['new_time']
            new_hair_length = request.form['new_hair_length']
            new_hairstyle = request.form['new_hairstyle']

            appointment = Appointment.query.filter_by(id=appointment_id).first()

            if not appointment:
                return jsonify({'response': 'Termin nije pronađen.'}), 404

            creds = authenticate_google_calendar()
            service = build('calendar', 'v3', credentials=creds)

            # Brisanje starog događaja
            service.events().delete(calendarId='primary', eventId=appointment.event_id).execute()

            # Kreiranje novog događaja sa novim podacima
            new_start_time = datetime.strptime(f"{new_date} {new_time}", '%Y-%m-%d %H:%M')
            new_end_time = new_start_time + timedelta(hours=1)

            new_start_time_utc = new_start_time.replace(tzinfo=timezone.utc)
            new_end_time_utc = new_end_time.replace(tzinfo=timezone.utc)

            event = {
                'summary': 'Frizerski Termin',
                'location': 'Frizerski Salon',
                'description': f'Frizura: {new_hairstyle}, Dužina kose: {new_hair_length}\n\nKontakt:\n{appointment.user.name} {appointment.user.surname}\nTelefon: {appointment.user.phone}\nEmail: {appointment.user.email}',
                'start': {
                    'dateTime': new_start_time_utc.isoformat(),
                    'timeZone': 'UTC',
                },
                'end': {
                    'dateTime': new_end_time_utc.isoformat(),
                    'timeZone': 'UTC',
                },
                'reminders': {
                    'useDefault': False,
                    'overrides': [
                        {'method': 'email', 'minutes': 24 * 60},
                        {'method': 'popup', 'minutes': 10},
                    ],
                },
            }

            new_event = service.events().insert(calendarId='primary', body=event).execute()

            # Ažuriranje baze podataka sa novim podacima
            appointment.date = new_date
            appointment.time = new_time
            appointment.hair_length = new_hair_length
            appointment.hairstyle = new_hairstyle
            appointment.event_id = new_event['id']
            db.session.commit()

            return jsonify({'response': 'Termin je uspešno izmenjen.'}), 200

        except Exception as e:
            print(f"Greška prilikom izmene termina: {str(e)}")
            return jsonify({'response': 'Greška prilikom izmene termina.'}), 500

    else:
        return render_template('promena.html')

@app.route('/handle_command', methods=['POST'])
@login_required
def handle_command():
    user_message = request.json['message'].lower().strip()
    if user_message == 'zakazati':
        return jsonify({'redirect': '/schedule_form'})
    else:
        payload = {"in-0": user_message, "user_id": "<USER or Conversation ID>"}
        result = query(payload)
        return jsonify({'response': result['outputs']['out-0']})

API_URL = "https://api.stack-ai.com/inference/v0/run/20c3467b-234a-4682-8fa3-7171ccd582e1/64fcaf58c75ddcf535c8d79a"
headers = {'Authorization': 'Bearer ed7901e0-dcaa-4b83-85af-028ef5aadf73', 'Content-Type': 'application/json'}

def query(payload):
    response = requests.post(API_URL, headers=headers, json=payload)
    return response.json()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            return redirect(url_for('home'))
        else:
            flash('Invalid email or password.')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/signin', methods=['GET', 'POST'])
def signin():
    if request.method == 'POST':
        name = request.form.get('name')
        surname = request.form.get('surname')
        email = request.form.get('email')
        phone = request.form.get('phone')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if user:
            flash('Email already exists.')
            return redirect(url_for('signin'))

        new_user = User(name=name, surname=surname, email=email, phone=phone, password=generate_password_hash(password, method='pbkdf2:sha256'))
        db.session.add(new_user)
        db.session.commit()
        flash('Account created successfully.')
        return redirect(url_for('home'))
        
    return render_template('singin.html')

@app.route('/forgotpassword', methods=['GET', 'POST'])
def forgotpassword():
    return render_template('forgot.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    return redirect(url_for('login'))

@app.route('/appointments', methods=['GET'])
@login_required
def appointments_page():
    return render_template('listazakazivanja.html')

@app.route('/obrisi_termin', methods=['GET','POST'])
@login_required
def obrisi_termin():
    try:
        appointment_id = request.form['appointment_id']
        
        appointment = Appointment.query.filter_by(id=appointment_id).first()

        if not appointment:
            return jsonify({'response': 'Termin nije pronađen.'}), 404

        creds = authenticate_google_calendar()
        service = build('calendar', 'v3', credentials=creds)

        # Brisanje događaja iz Google Kalendara
        service.events().delete(calendarId='primary', eventId=appointment.event_id).execute()

        # Brisanje termina iz baze podataka
        db.session.delete(appointment)
        db.session.commit()

        return jsonify({'response': 'Termin je uspešno obrisan.'}), 200

    except Exception as e:
        print(f"Greška prilikom brisanja termina: {str(e)}")
        return jsonify({'response': 'Greška prilikom brisanja termina.'}), 500


if __name__ == '__main__':
    app.run(debug=True,port=5000)


