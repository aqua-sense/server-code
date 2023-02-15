import datetime
from functools import wraps
import jwt
import shortuuid
from dotenv import dotenv_values
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from sqlalchemy.sql import func
from werkzeug.security import check_password_hash, generate_password_hash
from flask import Flask, jsonify, request

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
    public_id = db.Column(db.String(), unique=True, nullable=False)
    email = db.Column(db.String(), unique=True, nullable=False)
    name = db.Column(db.String(), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)
    enabled = db.Column(db.Boolean, nullable=False)

# Devices table - stores device information
class devices(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(), unique=True, nullable=False)
    owner_id = db.Column(db.String(), ForeignKey('users.public_id'))
    device_type = db.Column(db.String(), nullable=False)
    device_token = db.Column(db.String(), unique=True, nullable=False)
    device_linked = db.Column(db.Boolean, nullable=False)
    device_last_seen = db.Column(db.DateTime)

# Device Data table - stores device sensor data for processing
class device_data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(), ForeignKey('devices.device_id'), nullable=False)
    timestamp = db.Column(db.DateTime(), nullable=False)
    device_log_message = db.Column(db.String(), nullable=False)
    device_log_date = db.Column(db.DateTime(), nullable=False)

# Setup authentication wrappers
# account_required - does the user have a valid token and is the account enabled
def account_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return {"message": "The authentication token is missing or invalid"}, 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'The authentication token is missing, invalid or expired'}), 401
        if current_user is None:
            return {"message": "The authentication token is invalid, please request a new token",}, 401
        if not current_user.enabled:
            return {"message": "This account has been disabled. Please try again later",}, 403
        return f(current_user, *args, **kwargs)
    return decorator

# admin_required - does the user have a valid administrator token and is the account enabled
def admin_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return {"message": "The authentication token is missing"}, 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'The authentication token is invalid or expired'}), 401
        if not current_user.enabled:
            return {"message": "This account has been disabled. Please try again later",}, 403
        if current_user.name == 'developer-admin' == 'developer-admin':
            return f(current_user, *args, **kwargs)
        else:
            return jsonify({'message': 'This endpoint is for use with an administrator account only'}), 401
    return decorator

# account_owner_required - does the user have a valid token and is the account enabled and the owner of the device
def device_owner_required(f):
    @wraps(f)
    def decorator(device_id, *args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return {"message": "The authentication token is missing, invalid or expired"}, 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users.query.filter_by(public_id=data['public_id']).first()
            device = devices.query.filter_by(device_id=device_id).first()
        except:
            return jsonify({'message': 'The authentication token is invalid or expired'}), 401
        if not current_user.enabled:
            return {"message": "This account has been disabled. Please try again later",}, 403
        if current_user.public_id == device.owner_id:
            return f(current_user, *args, **kwargs)
    return decorator

# account_owner - does the user have a valid token and is the account enabled | returns the account id
def account_owner(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return {"message": "The authentication token is missing, invalid or expired"}, 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user = users.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message': 'The authentication token is invalid or expired'}), 401
        return f(user, *args, **kwargs)
    return decorator

@app.route('/create/account', methods=['PUT'])
def signup_user():  
    data = request.get_json()  
    try:
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = users(public_id=str(shortuuid.ShortUUID().random(length=5)), name=data['name'], password=hashed_password, email=data['email'], enabled=True) 
        db.session.add(new_user)  
    except KeyError:
        return jsonify({'message': 'One or more JSON Keys are invalid'}), 400
    try:
        db.session.commit()
    except db.exc.IntegrityError:
        return jsonify({'message': 'user already exists'}), 209
    return jsonify({'message': 'registeration successfull'}), 200

@app.route('/create/device', methods=['PUT'])
@admin_required
def create_device(e):
    data = request.get_json()
    device_id = shortuuid.ShortUUID().random(length=8)
    new_device = devices(device_id = device_id, device_type=data['device_type'], device_token=shortuuid.ShortUUID().random(length=5), device_linked=False)
    db.session.add(new_device)
    db.session.commit()
    return jsonify({'message': 'device created', "Device ID": device_id}), 200

@app.route('/get/authtoken', methods=['GET']) 
def login_user():
   auth = request.authorization  
   if not auth or not auth.username or not auth.password: 
       return jsonify({'message': 'login headers missing'}), 401
   user = users.query.filter_by(name=auth.username).first()  
   if user != None:
        if check_password_hash(user.password, auth.password):
            token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=60)}, app.config['SECRET_KEY'], "HS256")
            return jsonify({'token' : token})
        else:
            return jsonify({'message': 'Incorrect Login Details'}), 401
   else:
        return jsonify({'message': 'No such user exists'}), 401

@app.route('/get/devices', methods=['GET'])
@account_owner
def get_devices(e):
    device_list = devices.query.filter_by(owner_id=e.public_id).all()
    output = []
    for device in device_list:
        device_data = {}
        device_data['device_id'] = device.device_id
        device_data['device_type'] = device.device_type
        device_data['device_token'] = device.device_token
        device_data['device_linked'] = device.device_linked
        output.append(device_data)
    return jsonify(output)

# TODO: handle keyerror
@app.route('/register/device', methods=['POST'])
@account_owner
def update_device(e):
    data = request.get_json()
    device = devices.query.filter_by(device_id=data['device_id']).first()
    if device != None and not device.device_linked and device.device_token == data['device_token']:
        device.device_linked = True
        device.owner_id = e.public_id
        db.session.commit()
        return jsonify({'message': 'device linked'}), 200
    else:
        return jsonify({'message': 'device not found, already linked, or the token is incorrect'}), 404

# TODO: make endpoints for device data reporting, device data retrieval, device data deletion, and device un-linking

if  __name__ == '__main__':  
     app.run(debug=True)