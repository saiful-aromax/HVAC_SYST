from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import hashlib
import hmac
import json
import urllib
import urllib.parse
from urllib.request import urlopen, Request
import requests
from apscheduler.schedulers.background import BackgroundScheduler
import csv
from sqlalchemy import text
import time
from datetime import date, timedelta, datetime

#*********************Library*********************

BASE_URL       = "https://openapi.tuyaeu.com"
LOGIN_URL      = "/v1.0/token?grant_type=1"
ATTRIBUTES_URL = "/v2.0/cloud/thing/{device_id}/shadow/properties"

def make_request(url, params=None, headers=None):
    if params:
        url = url + "?" + urllib.parse.urlencode(params)
    request = Request(url, headers=headers or {})

    try:
        with urlopen(request, timeout=10) as response:
            return response, response.read().decode("utf-8")

    except Exception as error:
        return error, ""

def get_timestamp(now = datetime.now()):
    return str(int(datetime.timestamp(now)*1000))

def get_sign(payload, client_secret):
    byte_key = bytes(client_secret, 'UTF-8')
    message = payload.encode()
    sign = hmac.new(byte_key, message, hashlib.sha256).hexdigest()
    return sign.upper()

def get_access_token(now, client_id, client_secret):
    # now = datetime.now()

    timestamp = get_timestamp(now)
    string_to_sign = client_id + timestamp + "GET\n" + \
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" + \
        "\n" + \
        LOGIN_URL
    signed_string = get_sign(string_to_sign, client_secret)

    headers = {
            "client_id": client_id,
            "sign": signed_string,
            "t": timestamp,
            "mode": "cors",
            "sign_method": "HMAC-SHA256",
            "Content-Type": "application/json"
            }

    response, body = make_request(BASE_URL + LOGIN_URL, headers = headers)

    json_result = json.loads(body)["result"]
    access_token = json_result["access_token"]
    return access_token

def get_status(device_id, client_id, client_secret):
    access_token = get_access_token(datetime.now(), client_id, client_secret)
    url = ATTRIBUTES_URL.format(device_id=device_id)
    timestamp = get_timestamp(datetime.now())
    string_to_sign = client_id + access_token + timestamp + "GET\n" + \
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855\n" + \
        "\n" + \
        url
    
    # print('aromax: ' + string_to_sign)
    signed_string = get_sign(string_to_sign, client_secret)
    headers = {
            "client_id": client_id,
            "sign": signed_string,
            "access_token": access_token,
            "t": timestamp,
            "mode": "cors",
            "sign_method": "HMAC-SHA256",
            "Content-Type": "application/json"
            }

    response, body = make_request(BASE_URL + url, headers = headers)

    json_result = json.loads(body)
    properties = json_result["result"]["properties"]
    output = list()
    for item in properties:
        if ('value' in item) and ('code' in item):
            if (item['code'] == 'temp_set') or (item['code'] == 'temp_current') or (item['code'] == 'TempCurrent') or (item['code'] == 'TempSet') or (item['code'] == 'switch_1'):
                if (item['code'] == 'temp_current') or (item['code'] == 'TempSet') or (item['code'] == 'TempCurrent'):
                    output.append({item['code']: item['value'] / 10})
                elif (item['code'] == 'switch_1'):
                    if item['value'] == True:
                        output.append({'HeatPump': 'ON'})
                    else:
                        output.append({'HeatPump': 'OFF'})
                else:
                    output.append({item['code']: item['value']})
    return output

def set_temperature(device_id, temperature, client_id, client_secret):
    access_token = get_access_token(datetime.now(), client_id, client_secret)
    temperature = str(temperature)
    sign_url = "/v1.0/devices/" + device_id + "/commands"
    body_string = '{ "commands": [ { "code": "temp_set", "value": ' + temperature + ' } ] }'
    body_string_encoded = hashlib.sha256(body_string.encode()).hexdigest()

    sign_string1 = "POST\n" + body_string_encoded + "\n\n" + sign_url
    
    timestamp = get_timestamp(datetime.now())

    sign_string2 = client_id + access_token + timestamp + sign_string1
    
    command_url = "https://openapi.tuyaeu.com/v1.0/devices/" + device_id + "/commands"

    signed_string = get_sign(sign_string2, client_secret)
    
    headers = {
            "client_id": client_id,
            "sign": signed_string,
            "access_token": access_token,
            "t": timestamp,
            "mode": "cors",
            "sign_method": "HMAC-SHA256",
            "Content-Type": "application/json"
            }

    data = {
        "commands": [
            {"code": "temp_set", "value": temperature}
        ]
    }

    response = requests.post(command_url, data=body_string, headers=headers)

    if response.status_code == 200:
        return 1
    else:
        return 0
        
def set_heatpump(device_id, command, client_id, client_secret):
    access_token = get_access_token(datetime.now(), client_id, client_secret)
    sign_url = "/v1.0/devices/" + device_id + "/commands"
    body_string = '{ "commands": [ { "code": "switch_1", "value": ' + command + ' } ] }'
    body_string_encoded = hashlib.sha256(body_string.encode()).hexdigest()
    sign_string1 = "POST\n" + body_string_encoded + "\n\n" + sign_url
    
    timestamp = get_timestamp(datetime.now())

    sign_string2 = client_id + access_token + timestamp + sign_string1
    
    command_url = "https://openapi.tuyaeu.com/v1.0/devices/" + device_id + "/commands"

    signed_string = get_sign(sign_string2, client_secret)
    
    headers = {
            "client_id": client_id,
            "sign": signed_string,
            "access_token": access_token,
            "t": timestamp,
            "mode": "cors",
            "sign_method": "HMAC-SHA256",
            "Content-Type": "application/json"
            }

    response = requests.post(command_url, data=body_string, headers=headers)
    if response.status_code == 200:
        return 1
    else:
        return 0
        

#*********************Flask Framework*********************

app = Flask(__name__, static_folder="C:/Users/aromax/Documents/AroProjects/SmartEMS/SmartEMS/static/")
app.secret_key = "your_very_secret_key_here"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/aromax/Documents/AroProjects/SmartEMS/smart_ems.db'

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)


class Users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    
    
class Devices(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(80), unique=True, nullable=False)
    device_id = db.Column(db.String(128), nullable=False)
    type = db.Column(db.String(30), nullable=False)
    device_name = db.Column(db.String(80), unique=True, nullable=True)
    client_id = db.Column(db.String(80), unique=True, nullable=True)
    client_secret = db.Column(db.String(128), unique=True, nullable=True)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        user = Users.query.filter_by(email=email).first()

        if user and bcrypt.check_password_hash(user.password, password):
            session["email"] = user.email
            flash("Login successful!")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password")
    return render_template("login.html")

@app.route('/logout')
def logout():
    session.pop('email', None)
    return redirect(url_for('login'))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]
        hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")

        if Users.query.filter_by(email=email).first():
            flash("Username already exists.")
            return redirect(url_for("register"))

        new_user = Users(email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash("User created successfully!")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route('/')
def index():
    if 'email' in session:
        data = []
        devices = Devices.query.filter_by(email=session['email']).all()
        for device in devices:
            item = {}
            item['device_id'] = device.device_id
            item['type'] = device.type
            item['device_name'] = device.device_name
            item['client_id'] = device.client_id
            item['client_secret'] = device.client_secret
            if device.type == 'TRV':
                info = get_status(device.device_id, device.client_id, device.client_secret)
                item['state'] = f"Current Temp: {info[1]['temp_current']} :: Set Temp: {info[0]['temp_set']}"
            elif device.type == 'thermostat':
                info = get_status(device.device_id, device.client_id, device.client_secret)
                item['state'] = f"Current Temp: {info[1]['TempCurrent'] * 5} :: Set Temp: {info[0]['TempSet'] * 5}"
            elif device.type == 'socket':
                info = get_status(device.device_id, device.client_id, device.client_secret)
                item['state'] = f"Status: {info[0]['HeatPump']}"
            else:
                item['state'] = ""
            data.append(item)
        return render_template("index.html", data=data)
    return redirect(url_for("login"))

@app.route("/set_temp", methods=["GET"])
def set_temp():
    device_id = request.args.get("device_id")
    temperature = request.args.get("temperature")
    client_id = request.args.get("client_id")
    client_secret = request.args.get("client_secret")
    result = set_temperature(device_id, temperature, client_id, client_secret)
    if result == 1:
        return "1"
    else:
        return "0"
    
@app.route("/set_switch", methods=["GET"])
def set_switch():
    device_id = request.args.get("device_id")
    action = request.args.get("action")
    client_id = request.args.get("client_id")
    client_secret = request.args.get("client_secret")
    result = set_heatpump(device_id, action, client_id, client_secret)
    if result == 1:
        return "1"
    else:
        return "0"

# @app.route("/append_data", methods=["GET"])
def append_data(email='all'):
    # email = request.args.get("email")
    
    with app.app_context():
        if email == 'all':
            query = text("SELECT * FROM devices WHERE type IN ('thermostat', 'TRV') ORDER BY type;")
        else:
            query = text("SELECT * FROM devices WHERE email=:email AND type IN ('thermostat', 'TRV') ORDER BY type;")
            
        result = db.session.execute(query, {"email": email})
        users = result.fetchall()
        row_data = {
        'Date Time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'Timestamp': datetime.now().timestamp(),
        'Thermostat Current': None,
        'Thermostat Set': None,
        'Thermostat Status': 0,
        'TRV Room-1 Current': None,
        'TRV Room-1 Set': None,
        'TRV Room-2 Current': None,
        'TRV Room-2 Set': None
    }
        ThermostatStatus = 0
        for user in users:
            if user.type == 'thermostat':
                info = get_status(user.device_id, user.client_id, user.client_secret)
                row_data['Thermostat Current'] = float(info[1]['TempCurrent'] * 5)
                row_data['Thermostat Set'] = float(info[0]['TempSet'] * 5)
                if (row_data['Thermostat Set'] > row_data['Thermostat Current']):
                    row_data['Thermostat Status'] = 1
                    ThermostatStatus = 1
            else:
                if user.device_name == 'TRV Room-1':
                    info = get_status(user.device_id, user.client_id, user.client_secret)
                    row_data['TRV Room-1 Current'] = float(info[1]['temp_current'])
                    row_data['TRV Room-1 Set'] = float(info[0]['temp_set'])
                    
                elif user.device_name == 'TRV Room-2':
                    info = get_status(user.device_id, user.client_id, user.client_secret)
                    row_data['TRV Room-2 Current'] = float(info[1]['temp_current'])
                    row_data['TRV Room-2 Set'] = float(info[0]['temp_set'])
        
    with open('client_1.csv', mode='a', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=row_data.keys())
        writer.writerow(row_data)
    # return '1'

def get_open_weather(lat, long):
    API = '3bb980e89cfe2a2a202773ebe12144e7'
    url = f"https://api.openweathermap.org/data/2.5/weather?lat={lat}&lon={long}&appid={API}"
    response = requests.get(url)

    if response.status_code == 200:
        data = json.loads(response.text)
        data = {
        'user': None,
        'lat': lat,
        'long': long,
        'temp': data['main']['temp'],
        'feels_like': data['main']['feels_like'],
        'temp_min': data['main']['temp_min'],
        'temp_max': data['main']['temp_max'],
        'pressure': data['main']['pressure'],
        'humidity': data['main']['humidity'],
        'visibility': data['visibility'],
        'wind_speed': data['wind']['speed'],
        'wind_deg': data['wind']['deg'],
        'clouds_all': data['clouds']['all'],
        'sunrise': data['sys']['sunrise'],
        'sunset': data['sys']['sunset']
    }
    return data
    
def append_openweather():
    
    with app.app_context():
        query = text("SELECT * FROM users;")
        result = db.session.execute(query)
        users = result.fetchall()
        row_data = {
        'Date Time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'Timestamp': datetime.now().timestamp(),
        'user': None,
        'lat': None,
        'long': None,
        'temp': None,
        'feels_like': None,
        'temp_min': None,
        'temp_max': None,
        'pressure': None,
        'humidity': None,
        'visibility': None,
        'wind_speed': None,
        'wind_deg': None,
        'clouds_all': None,
        'sunrise': None,
        'sunset': None
    }
        for user in users:
            info = get_open_weather(user.lat, user.long)
            row_data['user'] = user.email
            row_data['lat'] = user.lat
            row_data['long'] = user.long
            row_data['temp'] = info['temp']
            row_data['feels_like'] = info['feels_like']
            row_data['temp_min'] = info['temp_min']
            row_data['temp_max'] = info['temp_max']
            row_data['pressure'] = info['pressure']
            row_data['humidity'] = info['humidity']
            row_data['visibility'] = info['visibility']
            row_data['wind_speed'] = info['wind_speed']
            row_data['wind_deg'] = info['wind_deg']
            row_data['clouds_all'] = info['clouds_all']
            row_data['sunrise'] = info['sunrise']
            row_data['sunset'] = info['sunset']
        
    with open('openweather.csv', mode='a', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=row_data.keys())
        writer.writerow(row_data)
        
def generate_hourly_datetimes(from_date: str, to_date: str) -> list:

    start_datetime = datetime.strptime(from_date, '%Y-%m-%d %H:%M:%S')
    end_datetime = datetime.strptime(to_date, '%Y-%m-%d %H:%M:%S')
    datetime_list = []
    current_datetime = start_datetime
    while current_datetime <= end_datetime:
        datetime_list.append(current_datetime.strftime('%Y-%m-%d %H:%M:%S'))
        current_datetime += timedelta(hours=1)
    return datetime_list

def datetime_to_timestamp(date_time_str):
    date_time_format = "%Y-%m-%d %H:%M:%S"
    dt_obj = datetime.strptime(date_time_str, date_time_format)
    timestamp = dt_obj.timestamp()
    return int(timestamp)
        
def get_open_weather_historical_info(lat, long, timestamp):
    API = '3bb980e89cfe2a2a202773ebe12144e7'
    url = f"https://api.openweathermap.org/data/3.0/onecall/timemachine?lat={lat}&lon={long}&dt={timestamp}&appid={API}"
    response = requests.get(url)

    if response.status_code == 200:
        data = json.loads(response.text)
        data = {
        'user': 'fstatazizi@gmail.com',
        'lat': data['lat'],
        'long': data['lon'],
        'timestamp': timestamp,
        'sunrise': data['data'][0]['sunrise'],
        'sunset': data['data'][0]['sunset'],
        'temp': data['data'][0]['temp'],
        'feels_like': data['data'][0]['feels_like'],
        'pressure': data['data'][0]['pressure'],
        'humidity': data['data'][0]['humidity'],
        'dew_point': data['data'][0]['dew_point'],
        'clouds': data['data'][0]['clouds'],
        'visibility': data['data'][0]['visibility'],
        'wind_speed': data['data'][0]['wind_speed'],
        'wind_deg': data['data'][0]['wind_deg'],
        'wind_gust': data['data'][0]['wind_gust'],
        'weather_main': data['data'][0]['weather'][0]['main'],
        'weather_description': data['data'][0]['weather'][0]['description']
    }
    return data
        
def get_historical_data():
    
    with app.app_context():
        row_data = {
        'user': None,
        'date_time': None,
        'timestamp': None,
        'lat': None,
        'long': None,
        'sunrise': None,
        'sunset': None,
        'temp': None,
        'feels_like': None,
        'pressure': None,
        'humidity': None,
        'dew_point': None,
        'clouds': None,
        'visibility': None,
        'wind_speed': None,
        'wind_deg': None,
        'wind_gust': None,
        'weather_main': None,
        'weather_description': None
    }
        from_date = '2023-06-08 00:00:00'
        to_date = '2024-06-07 23:00:00'
        date_time_list = generate_hourly_datetimes(from_date, to_date)
        lat = '53.276220'
        long = '-6.227920'
        for date_time in date_time_list:
            timestamp_value = datetime_to_timestamp(date_time)
            info = get_open_weather_historical_info(lat, long, timestamp_value)
            row_data['user'] = 'fstatazizi@gmail.com'
            row_data['date_time'] = date_time
            row_data['timestamp'] = timestamp_value
            row_data['lat'] = info['lat']
            row_data['long'] = info['long']
            row_data['sunrise'] = info['sunrise']
            row_data['sunset'] = info['sunset']
            row_data['temp'] = info['temp']
            row_data['feels_like'] = info['feels_like']
            row_data['pressure'] = info['pressure']
            row_data['humidity'] = info['humidity']
            row_data['dew_point'] = info['dew_point']
            row_data['clouds'] = info['clouds']
            row_data['visibility'] = info['visibility']
            row_data['wind_speed'] = info['wind_speed']
            row_data['wind_deg'] = info['wind_deg']
            row_data['wind_gust'] = info['wind_gust']
            row_data['weather_main'] = info['weather_main']
            row_data['weather_description'] = info['weather_description']
        
    with open('historical_data.csv', mode='a', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=row_data.keys())
        writer.writerow(row_data)
    


# def append_data_request():
#     response = requests.get('http://127.0.0.1:5000/append_data?email=saiful.aromax@gmail.com')
#     if response.status_code == 200:
#         print("GET request executed successfully")
#     else:
#         print("Failed to execute GET request")
# scheduler = BackgroundScheduler()
# scheduler.add_job(append_data_request, 'interval', minutes=1)
# scheduler.start()

# Schedule the job to execute every minute

scheduler = BackgroundScheduler()
scheduler.add_job(append_data, 'interval', seconds=5, args=['saiful.aromax@gmail.com'])
scheduler.add_job(append_openweather, 'interval', seconds=5)
scheduler.start()

if __name__ == "__main__":
    # app.run(host="0.0.0.0", debug=True)
    app.run(debug=False)
