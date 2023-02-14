from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import ForeignKey
from werkzeug.security import generate_password_hash, check_password_hash
import shortuuid
import jwt
import datetime
from functools import wraps
from dotenv import dotenv_values

app = Flask(__name__)
config = dotenv_values()
app.config['SECRET_KEY'] = config['SECRET_KEY']
app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql+psycopg2://{user}:{pw}@{url}/{db}'.format(user = config['DATABASE_USER'], pw = config['DATABASE_PASSWORD'], url = config['DATABASE_HOST'], db = config['DATABASE_NAME'])
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class users(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    public_id = db.Column(db.String(), unique=True, nullable=False)
    email = db.Column(db.String(), unique=True, nullable=False)
    name = db.Column(db.String(), unique=True, nullable=False)
    password = db.Column(db.String(), nullable=False)

class devices(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(), unique=True, nullable=False)
    owner_id = db.Column(db.String(), ForeignKey('users.public_id'))
    device_type = db.Column(db.String(), nullable=False)
    device_token = db.Column(db.String(), unique=True, nullable=False)
    device_linked = db.Column(db.Boolean, nullable=False)
    device_last_seen = db.Column(db.DateTime)

class device_data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.String(), ForeignKey('devices.device_id'), nullable=False)
    timestamp = db.Column(db.DateTime(), nullable=False)
    device_log_message = db.Column(db.String(), nullable=False)
    device_log_date = db.Column(db.DateTime(), nullable=False)

def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return {"message": "The authentication token is missing, invalid or expired"}, 401
        
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users.query.filter_by(public_id=data['public_id']).first()
            if current_user is None:
                return {
                "message": "The authentication token is missing, invalid or expired",}, 401
        except:
            return jsonify({'message': 'The authentication token is missing, invalid or expired'}), 401
        return f(current_user, *args, **kwargs)
    return decorator

def admin_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return {"message": "The authentication token is missing, invalid or expired"}, 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users.query.filter_by(public_id=data['public_id']).first()
            if current_user.name == 'developer-admin':
                return f(current_user, *args, **kwargs)
        except:
            return jsonify({'message': 'The authentication token is missing, invalid or expired'}), 401
        return jsonify({'message': 'The authentication token is missing, invalid or expired'}), 401
    return decorator

def account_owner_required(f):
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
            if current_user.public_id == device.owner_id:
                return f(current_user, *args, **kwargs)
        except:
            return jsonify({'message': 'The authentication token is missing, invalid or expired'}), 401
        return jsonify({'message': 'The authentication token is missing, invalid or expired'}), 401
    return decorator

@app.route('/create/account', methods=['POST'])
def signup_user():  
    data = request.get_json()  
    try:
        hashed_password = generate_password_hash(data['password'], method='sha256')
        new_user = users(public_id=str(shortuuid.ShortUUID().random(length=5)), name=data['name'], password=hashed_password, email=data['email']) 
        db.session.add(new_user)  
    except KeyError:
        return jsonify({'message': 'One or more JSON Keys are invalid'}), 400
    try:
        db.session.commit()
    except db.exc.IntegrityError:
        return jsonify({'message': 'user already exists'}), 209
    return jsonify({'message': 'registeration successfull'}), 200

@app.route('/login/authtoken', methods=['GET']) 
def login_user():
   auth = request.authorization  
   if not auth or not auth.username or not auth.password: 
       return jsonify({'message': 'login headers missing'}), 401
   user = users.query.filter_by(name=auth.username).first()  
   if user != None:
        if check_password_hash(user.password, auth.password):
            token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
            return jsonify({'token' : token})
        else:
            return jsonify({'message': 'Incorrect Login Details'}), 401
   else:
        return jsonify({'message': 'No such user exists'}), 401

@app.route('/resetdb', methods=['GET'])
@admin_required
def resetdb_command(e):
    db.drop_all()
    db.create_all()
    return 'Database reset'

@app.route('/users', methods=['GET'])
@admin_required
def get_all_users(e):  
    userdatabase = users.query.all() 
    result = []   
    for user in userdatabase:   
        user_data = {}   
        user_data['public_id'] = user.public_id  
        user_data['email'] = user.email
        user_data['name'] = user.name 
        result.append(user_data)   
    return jsonify({'users': result})

@app.route('/devices', methods=['GET'])
@token_required
def get_all_devices(e):
    devicedatabase = devices.query.all()
    result = []
    for device in devicedatabase:
        device_data = {}
        device_data['device_id'] = device.device_id
        device_data['device_type'] = device.device_type
        device_data['device_token'] = device.device_token
        device_data['device_linked'] = device.device_linked
        device_data['device_last_seen'] = device.device_last_seen
        device_data['device_ip'] = device.device_ip
        result.append(device_data)
    return jsonify({'devices': result})

@app.route('/devices/<device_id>', methods=['GET'])
@account_owner_required
def get_device(e, device_id):
    device = devices.query.filter_by(device_id=device_id).first()
    if device is None:
        return jsonify({'message': 'No such device exists'}), 404
    device_data = {}
    device_data['device_id'] = device.device_id
    device_data['device_type'] = device.device_type
    device_data['device_token'] = device.device_token
    device_data['device_linked'] = device.device_linked
    return jsonify(device_data)

@app.route('/register/device', methods=['POST'])
@token_required
def update_device(e):
    data = request.get_json()
    new_device = devices(device_id=shortuuid.ShortUUID().random(length=8), owner_id = 'tx5rYSCZAg6CRCrvD6wxmp', device_type=data['device_type'], device_token=data['device_token'], device_linked=False, device_ip=data['device_ip'])
    db.session.add(new_device)
    db.session.commit()
    return jsonify({'message': 'device updated'})

@app.route('/create/device', methods=['POST'])
@admin_required
def create_device(e):
    data = request.get_json()
    device_id = shortuuid.ShortUUID().random(length=8)
    new_device = devices(device_id = device_id, device_type=data['device_type'], device_token=shortuuid.ShortUUID().random(length=5), device_linked=False)
    db.session.add(new_device)
    db.session.commit()
    return jsonify({'message': 'device created', "Device ID": device_id}), 200

if  __name__ == '__main__':  
     app.run(debug=True)