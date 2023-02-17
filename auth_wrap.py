from functools import wraps

import jwt
from flask import jsonify, request


# Setup authentication wrappers
# account_required - does the user have a valid token and is the account enabled
def account_required(f):
    @wraps(f)
    def decorator(app, users, *args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return {"message": "The authentication token is missing or invalid"}, 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users.query.filter_by(user_id=data['user_id']).first()
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
    def decorator(app, users, *args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return {"message": "The authentication token is missing"}, 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users.query.filter_by(user_id=data['user_id']).first()
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
    def decorator(app, users, device_id, *args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return {"message": "The authentication token is missing, invalid or expired"}, 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            current_user = users.query.filter_by(user_id=data['user_id']).first()
            device = devices.query.filter_by(device_id=device_id).first()
        except:
            return jsonify({'message': 'The authentication token is invalid or expired'}), 401
        if not current_user.enabled:
            return {"message": "This account has been disabled. Please try again later",}, 403
        if current_user.user_id == device.owner_id:
            return f(current_user, *args, **kwargs)
    return decorator

# account_owner - does the user have a valid token and is the account enabled | returns the account id
def account_owner(f):
    @wraps(f)
    def decorator(app, users, *args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return {"message": "The authentication token is missing, invalid or expired"}, 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            user = users.query.filter_by(user_id=data['user_id']).first()
        except:
            return jsonify({'message': 'The authentication token is invalid or expired'}), 401
        return f(user, *args, **kwargs)
    return decorator

def device_endpoint(f):
    @wraps(f)
    def decorator(app, users, devices, *args, **kwargs):
        token = None
        if "Authorization" in request.headers:
            token = request.headers["Authorization"].split(" ")[1]
        if not token:
            return {"message": "The authentication token is missing, invalid or expired"}, 401
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            device = devices.query.filter_by(device_id=data['device_id']).first()
            token = device.device_token
            id = device.device_id
            if device == None or device.device_token != data['device_token']:
                return jsonify({'message': 'The authentication token is invalid'}), 401
        except:
            return jsonify({'message': 'The authentication token is invalid'}), 401
        return f(token, id, *args, **kwargs)
    return decorator