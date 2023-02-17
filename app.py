import datetime

import jwt
import shortuuid
from dotenv import dotenv_values
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.ext.mutable import MutableDict
from sqlalchemy.sql import func
from werkzeug.security import check_password_hash, generate_password_hash

# Setup Flask amd SQLAlchemy
app = Flask(__name__)
config = dotenv_values()
app.config['SECRET_KEY'] = config['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user = config['DATABASE_USER'], pw = config['DATABASE_PASSWORD'], url = config['DATABASE_HOST'], db = config['DATABASE_NAME'])
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Setup Database Models
# Users table - stores user information
class users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.String(), unique=True, nullable=False)
    user_email = db.Column(db.String(), unique=True, nullable=False)
    user_name = db.Column(db.String(), unique=True, nullable=False)
    user_password = db.Column(db.String(), nullable=False)
    user_enabled = db.Column(db.Boolean, nullable=False)

# Devices table - stores device information
class devices(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(), unique=True, nullable=False)
    device_owner_id = db.Column(db.String(), ForeignKey('users.user_id'))
    device_type = db.Column(db.String(), nullable=False)
    device_token = db.Column(db.String(), unique=True, nullable=False)
    device_linked = db.Column(db.Boolean, nullable=False)
    device_last_seen = db.Column(db.DateTime)

# Device Data table - stores device sensor data for processing
class device_data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_log_id = db.Column(db.String(), ForeignKey('devices.device_id'), nullable=False)
    device_log_timestamp = db.Column(db.DateTime(), nullable=False)
    device_log_message = db.Column(MutableDict.as_mutable(JSONB), nullable=False)

from auth_wrapper import (account_owner, admin_required, device_endpoint,
                          device_owner_required)

@app.route('/register/account', methods=['POST'])
def signup_user():  
    data = request.get_json()  
    try:
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = users(user_id=str(shortuuid.ShortUUID().random(length=5)), user_name=data['username'], user_password=hashed_password, user_email=data['email'], user_enabled=True) 
        db.session.add(new_user)  
    except KeyError as e:
        return jsonify({'message': 'One or more JSON Keys are invalid', "error": str(e)}), 400
    try:
        db.session.commit()
    except db.exc.IntegrityError:
        return jsonify({'message': 'username or email already exists'}), 209
    return jsonify({'message': 'registration successful'}), 200

@app.route('/register/device', methods=['POST'])
@account_owner
def update_device(e):
    data = request.get_json()
    try:
        device = devices.query.filter_by(device_id=data['device_id']).first()
        if device != None and not device.device_linked and device.device_token == data['device_token']:
            device.device_linked = True
            device.owner_id = e.user_id
            db.session.commit()
            return jsonify({'message': 'device linked'}), 200
        else:
            return jsonify({'message': 'device not found, already linked, or the token is incorrect'}), 404
    except KeyError:
        return jsonify({'message': 'One or more JSON Keys are invalid'}), 400
    except:
        return jsonify({'message': 'An unknown error occured'}), 500

# TODO: handle keyerror
@app.route('/create/device', methods=['POST'])
@admin_required
def create_device(e):
    data = request.get_json()
    try:
        device_id = shortuuid.ShortUUID().random(length=8)
        new_device = devices(device_id = device_id, device_type=data['device_type'], device_token=shortuuid.ShortUUID().random(length=5), device_linked=False)
        db.session.add(new_device)
    except KeyError:
        return jsonify({'message': 'One or more JSON Keys are invalid'}), 400
    db.session.commit()
    return jsonify({'message': 'device created', "device_id": device_id}), 200

@app.route('/get/user/authtoken', methods=['GET']) 
def generate_token():
   auth = request.authorization  
   if not auth or not auth.username or not auth.password: 
       return jsonify({'message': 'login headers missing'}), 401
   user = users.query.filter_by(user_name=auth.username).first()  
   if user != None:
        if check_password_hash(user.password, auth.password):
            token = jwt.encode({'user_id' : user.user_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=60)}, app.config['SECRET_KEY'], "HS256")
            return jsonify({'token' : token}), 200
        else:
            return jsonify({'message': 'Incorrect Login Details'}), 401
   else:
        return jsonify({'message': 'No such user exists'}), 401
    
@app.route('/get/device/authtoken', methods=['GET'])
@admin_required
def generate_device_token(e):
    data = request.get_json()
    try:
        device_id = data["device_id"]
        device_token = data["device_token"]
        device = devices.query.filter_by(device_id=device_id).first()
        if device != None and device.device_token == device_token:
            token = jwt.encode({'device_id' : device_id, "device_token" : device_token}, app.config['SECRET_KEY'], "HS256")
            return jsonify({'token' : token}), 200
        else:
            return jsonify({'message': 'device not found or the token is incorrect'}), 404
    except KeyError:
        return jsonify({'message': 'One or more JSON Keys are invalid'}), 400

@app.route('/get/devices', methods=['GET'])
@account_owner
def get_devices(e):
    device_list = devices.query.filter_by(owner_id=e.user_id).all()
    output = []
    for device in device_list:
        device_data = {}
        device_data['device_id'] = device.device_id
        device_data['device_type'] = device.device_type
        device_data['device_token'] = device.device_token
        device_data['device_linked'] = device.device_linked
        output.append(device_data)
    return jsonify(output)

@app.route('/get/device/<device_id>', methods=['GET'])
@device_owner_required
def get_device(e, device_id):
    device = devices.query.filter_by(device_id=device_id).first()
    if device is None:
        return jsonify({'message': 'No such device exists'}), 404
    if device.owner_id != e.user_id:
        return jsonify({'message': 'You do not own this device'}), 403
    device_data = {}
    device_data['device_id'] = device.device_id
    device_data['device_type'] = device.device_type
    device_data['device_token'] = device.device_token
    device_data['device_linked'] = device.device_linked
    return jsonify(device_data)

@app.route('/get/account', methods=['GET'])
@account_owner
def get_account(e):
    user = users.query.filter_by(user_id=e.user_id).first()
    user_data = {}
    user_data['user_id'] = user.user_id
    user_data['name'] = user.user_name
    user_data['email'] = user.user_email
    user_data['enabled'] = user.user_enabled
    return jsonify(user_data)

@app.route('/delete/device/<device_id>', methods=['DELETE'])
@device_owner_required
def delete_device(e, device_id):
    device = devices.query.filter_by(device_id=device_id).first()
    if device is None:
        return jsonify({'message': 'No such device exists'}), 404
    if device.owner_id != e.user_id:
        return jsonify({'message': 'You do not own this device'}), 403
    db.session.delete(device)
    db.session.commit()
    return jsonify({'message': 'device deleted'}), 200

@app.route('/delete/account', methods=['DELETE'])
@account_owner
def delete_account(e):
    user = users.query.filter_by(user_id=e.user_id).first()
    db.session.delete(user)
    db.session.commit()
    return jsonify({'message': 'account deleted'}), 200

@app.route('/delete/database', methods=['DELETE'])
#@admin_required
def resetdb_command():
    db.drop_all()
    db.create_all()
    admin = users(user_id='admin', user_name='developer-admin', user_password='sha256$7cp16Nl2XE9uSn0B$49866d0a3c91f07177b4a44e75e395820cb5d832f608b9b115b0f2e5d8051516', user_email='none', user_enabled=True) 
    db.session.add(admin)  
    db.session.commit()
    return jsonify({'message': 'database reset'}), 200

@app.route('/update/account', methods=['POST'])
@account_owner
def update_account(e):
    data = request.get_json()
    user = users.query.filter_by(user_id=e.user_id).first()
    try:
        user.user_name = data['name']
        user.user_email = data['email']
    except KeyError:
        return jsonify({'message': 'One or more JSON Keys are invalid'}), 400
    db.session.commit()
    return jsonify({'message': 'account updated'}), 200

@app.route('/update/password', methods=['POST'])
@account_owner
def update_password(e):
    data = request.get_json()
    user = users.query.filter_by(user_id=e.user_id).first()
    try:
        if check_password_hash(user.password, data['old_password']):
            user.user_password = generate_password_hash(data['new_password'], method='sha256')
        else:
            return jsonify({'message': 'Incorrect Password'}), 401
    except KeyError:
        return jsonify({'message': 'One or more JSON Keys are invalid'}), 400
    db.session.commit()
    return jsonify({'message': 'password updated'}), 200

@app.route('/post/device/<device_id>', methods=['POST'])
@device_owner_required
def post_device(e, device_id):
    data = request.get_json()
    device = devices.query.filter_by(device_id=device_id).first()
    if device is None:
        return jsonify({'message': 'No such device exists'}), 404
    if device.owner_id != e.user_id:
        return jsonify({'message': 'You do not own this device'}), 403
    if device.device_linked == False:
        return jsonify({'message': 'Device is not linked'}), 403
    try:
        device.log_message = data['log_message']
        device.timestamp = func.now()
        device.device_log_date = data['log_date']
    except KeyError:
        return jsonify({'message': 'One or more JSON Keys are invalid'}), 400
    db.session.commit()
    return jsonify({'message': 'device log posted'}), 200

# TODO: make endpoints for device data reporting, device data retrieval
@app.route('/post/device/<device_id>/data', methods=['POST'])
@device_endpoint
def post_device_data(e):
    data = request.get_json()
    device = devices.query.filter_by(device_id=e.id).first()
    if device is None:
        return jsonify({'message': 'No such device exists'}), 404
    if device.owner_id != e.user_id:
        return jsonify({'message': 'You do not own this device'}), 403
    if device.device_linked == False:
        return jsonify({'message': 'Device is not linked'}), 403
    try:
        device.device_data = data['device_data']
        device.timestamp = func.now()
        db.session.commit()
    except KeyError:
        return jsonify({'message': 'One or more JSON Keys are invalid'}), 400
    except:
        return jsonify({'message': 'Internal Server Error'}), 500
    return jsonify({'message': 'device data posted'}), 200

@app.route('/get/device/<device_id>/latestdata', methods=['GET'])
@device_owner_required
def get_device_data(e, get_device_id):
    device = devices.query.filter_by(device_id=get_device_id).first()
    if device is None:
        return jsonify({'message': 'No such device exists'}), 404
    if device.owner_id != e.user_id:
        return jsonify({'message': 'You do not own this device'}), 403
    if device.device_linked == False:
        return jsonify({'message': 'Device is not linked'}), 403
    return jsonify({'device_data': device.device_data}), 200

if  __name__ == '__main__':  
     app.run(debug=True)