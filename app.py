from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
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
    user_id = db.Column(db.Integer)
    device_type = db.Column(db.String(), nullable=False)
    device_token = db.Column(db.String(), unique=True, nullable=False)
    device_linked = db.Column(db.Boolean, nullable=False)
    device_last_seen = db.Column(db.DateTime)
    device_ip = db.Column(db.String())

class device_data(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer)
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
            return {
                "message": "Authentication Token is missing!",
                "data": None,
                "error": "Unauthorized"
            }, 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users.query.filter_by(public_id=data['public_id']).first()
            if current_user is None:
                return {
                "message": "Invalid Authentication token!",
                "data": None,
                "error": "Unauthorized"
            }, 401
        except:
            return jsonify({'message': 'token is invalid'})
        return f(current_user, *args, **kwargs)
    return decorator


@app.route('/register', methods=['POST'])
def signup_user():  
    data = request.get_json()  
    hashed_password = generate_password_hash(data['password'], method='sha256')
    new_user = users(public_id=str(uuid.uuid4()), name=data['name'], password=hashed_password, email=data['email']) 
    db.session.add(new_user)  
    try:
        db.session.commit()    
    except db.exc.IntegrityError:
        return jsonify({'message': 'user already exists'}), 209
    return jsonify({'message': 'registeration successfull'}), 200

@app.route('/login', methods=['POST']) 
def login_user():
   auth = request.authorization  
   if not auth or not auth.username or not auth.password: 
       return make_response('could not verify', 401, {'Authentication': 'login required"'})   
   user = users.query.filter_by(name=auth.username).first()  
   if check_password_hash(user.password, auth.password):
       token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=45)}, app.config['SECRET_KEY'], "HS256")
       return jsonify({'token' : token})
   return make_response('could not verify',  401, {'Authentication': '"login required"'})

@app.route('/resetdb', methods=['GET'])
@token_required
def resetdb_command():
    db.drop_all()
    db.create_all()
    return 'Database reset'

@app.route('/users', methods=['GET'])
@token_required
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

if  __name__ == '__main__':  
     app.run()