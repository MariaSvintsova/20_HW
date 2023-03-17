import calendar
import datetime
import hashlib
import base64
import jwt
from flask import request, abort
from flask_restx import Resource, Namespace
from constants import PWD_HASH_SALT, PWD_HASH_ITERATIONS
from dao.model.user import User
from setup_db import db

auth_ns = Namespace('auth')


secret = 's3cR$eT'
algo = 'HS256'

@auth_ns.route('/')
class AuthView(Resource):
    def post(self):
        req_json = request.json
        username = req_json.get('username')
        password = req_json.get('password')

        if password == None or username == None:
            abort(401)

        user = db.session.query(User).filter(User.username == username).first()

        if user == None:
            return {"error": "Неверные учётные данные"}, 401

        hash_password = base64.b64encode(hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'),  PWD_HASH_SALT, PWD_HASH_ITERATIONS))
        print(hash_password, user.password)
        if hash_password != user.password:
            return {"error": "Неверные учётные данные"}, 401

        data = {'username': username,
                'role': user.role}

        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data['exp'] = calendar.timegm(min30.timetuple())
        access_token = jwt.encode(data, secret, algorithm=algo)

        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data['exp'] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(data, secret, algorithm=algo)

        tokens = {'access_token': access_token, 'refresh_token':refresh_token}

        return tokens

    def put(self):
        req_json = request.json
        refresh_token = req_json.get('refresh_token')

        if refresh_token == None:
            abort(401)

        try:
            data = jwt.decode(jwt=refresh_token, key=secret, algorithms=[algo])
        except Exception as e:
            abort(400)

        username = data.get('username')

        user = db.session.query(User).filter(User.username == username).first()

        data = {
            'username': user.username,
            'role': user.role
        }

        min30 = datetime.datetime.utcnow() + datetime.timedelta(minutes=30)
        data['exp'] = calendar.timegm(min30.timetuple())
        access_token = jwt.encode(data, secret, algorithm=algo)

        days130 = datetime.datetime.utcnow() + datetime.timedelta(days=130)
        data['exp'] = calendar.timegm(days130.timetuple())
        refresh_token = jwt.encode(data, secret, algorithm=algo)

        tokens = {'access_token': access_token, 'refresh_token': refresh_token}

        return tokens

def auth_reqiured(func):
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split('Bearer ')[-1]

        try:
            jwt.decode(token, secret, algorithms=[algo])
        except Exception as e:
            abort(401)
            return 'JWT decode exception', e

        return func(*args, **kwargs)
    return wrapper

def admin_required(func):
    def wrapper(*args, **kwargs):
        if 'Authorization' not in request.headers:
            abort(401)

        data = request.headers['Authorization']
        token = data.split('Bearer ')[-1]

        try:
            sl = jwt.decode(token, secret, algorithms=[algo])
            if sl["role"] == 'admin':
                return func(*args, **kwargs)
            else:
                abort(403)
                return 'Allowed only for admins'
        except Exception as e:
            abort(401)
            return 'JWT decode exception', e
    return wrapper


