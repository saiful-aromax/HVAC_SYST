from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import hashlib
import hmac
import json
import urllib
import urllib.parse
from urllib.request import urlopen, Request
from datetime import datetime
import requests
from threading import Lock
from apscheduler.schedulers.background import BackgroundScheduler
import csv
from sqlalchemy import text
import time

app = Flask(__name__, static_folder="C:/Users/aromax/Documents/AroProjects/SmartEMS/SmartEMS/static/")
app.secret_key = "your_very_secret_key_here"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///C:/Users/aromax/Documents/AroProjects/SmartEMS/smart_ems.db'

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
            
def get_device_list(email='all'):
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
        'Thermostat Status': None,
        'TRV Room-1 Current': None,
        'TRV Room-1 Set': None,
        'TRV Room-2 Current': None,
        'TRV Room-2 Set': None
    }
        for user in users:
            if user.type == 'thermostat':
                
                current_time = datetime.now()
                current_timestamp = time.time()
                print(current_timestamp)
        
    with open('data.csv', mode='a', newline='') as file:
        writer = csv.DictWriter(file, fieldnames=row_data.keys())
        writer.writerow(row_data)

scheduler = BackgroundScheduler()
scheduler.add_job(get_device_list, 'interval', minutes=1, args=['saiful.aromax@gmail.com'])
scheduler.start()

if __name__ == "__main__":
    # app.run(host="0.0.0.0", debug=True)
    # This is AROMAX
    app.run(debug=False)
