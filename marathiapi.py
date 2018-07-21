from flask import Flask, request, jsonify, make_response
from flask_sqlalchemy import SQLAlchemy
import uuid
from werkzeug.security import generate_password_hash, check_password_hash
import jwt
import datetime
from functools import wraps
import os

basedir = os.path.abspath(os.path.dirname(__file__))
app = Flask(__name__)

app.config['SECRET_KEY'] = 'thisissecret'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(basedir, 'dictionary.sqlite')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column('id', db.Integer, primary_key=True)
    public_id = db.Column('public_id', db.String(50), unique=True)
    email = db.Column('email', db.String(50))
    password = db.Column('password', db.String(80))
    admin = db.Column('admin', db.Boolean)

class EnglishMarathi(db.Model):
    __tablename__ = 'EnglishMarathi'
    Key = db.Column('Key', db.String(150), primary_key=True)
    Meaning1 = db.Column('Meaning1', db.String(150))
    Meaning2 = db.Column('Meaning2', db.String(150))
    Meaning3 = db.Column('Meaning3', db.String(150))
    Meaning4 = db.Column('Meaning4', db.String(150))

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None

        if 'x-access-token' in request.headers:
            token = request.headers['x-access-token']

        if not token:
            return jsonify({'message' : 'Token is missing!'}), 401

        try: 
            data = jwt.decode(token, app.config['SECRET_KEY'])
            current_user = User.query.filter_by(public_id=data['public_id']).first()
        except:
            return jsonify({'message' : 'Token is invalid!'}), 401

        return f(current_user, *args, **kwargs)

    return decorated

@app.route('/user', methods=['GET'])
@token_required
def get_all_users(current_user):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    users = User.query.all()

    output = []

    for user in users:
        user_data = {}
        user_data['public_id'] = user.public_id
        user_data['email'] = user.email
        user_data['password'] = user.password
        user_data['admin'] = user.admin
        output.append(user_data)

    return jsonify({'users' : output})

@app.route('/user/<public_id>', methods=['GET'])
@token_required
def get_one_user(current_user, public_id):

    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user_data = {}
    user_data['public_id'] = user.public_id
    user_data['email'] = user.email
    user_data['password'] = user.password
    user_data['admin'] = user.admin

    return jsonify({'user' : user_data})

@app.route('/user', methods=['POST'])
@token_required
def create_user(current_user):    
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    data = request.get_json()

    hashed_password = generate_password_hash(data['password'], method='sha256')

    new_user = User(public_id=str(uuid.uuid4()), email=data['email'], password=hashed_password, admin=False)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({'message' : 'New user created!'})

@app.route('/user/<public_id>', methods=['PUT'])
@token_required
def promote_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    user.admin = True
    db.session.commit()

    return jsonify({'message' : 'The user has been promoted!'})

@app.route('/user/<public_id>', methods=['DELETE'])
@token_required
def delete_user(current_user, public_id):
    if not current_user.admin:
        return jsonify({'message' : 'Cannot perform that function!'})

    user = User.query.filter_by(public_id=public_id).first()

    if not user:
        return jsonify({'message' : 'No user found!'})

    db.session.delete(user)
    db.session.commit()

    return jsonify({'message' : 'The user has been deleted!'})

@app.route('/login')
def login():
    auth = request.authorization

    if not auth or not auth.username or not auth.password:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    user = User.query.filter_by(email=auth.username).first()

    if not user:
        return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

    if check_password_hash(user.password, auth.password):
        token = jwt.encode({'public_id' : user.public_id, 'exp' : datetime.datetime.utcnow() + datetime.timedelta(minutes=30)}, app.config['SECRET_KEY'])

        return jsonify({'token' : token.decode('UTF-8')})

    return make_response('Could not verify', 401, {'WWW-Authenticate' : 'Basic realm="Login required!"'})

@app.route('/engmar', methods=['GET'])
@token_required
def get_all_engmar(current_user):
    engmars = EnglishMarathi.query.all()

    output = []

    for engmar in engmars:
        engmar_data = {}
        engmar_data['Key'] = engmar.Key
        engmar_data['Meaning1'] = engmar.Meaning1
        engmar_data['Meaning2'] = engmar.Meaning2
        engmar_data['Meaning3'] = engmar.Meaning3
        engmar_data['Meaning4'] = engmar.Meaning4
        output.append(engmar_data)

    return jsonify({'engmars' : output})

@app.route('/engmar/<engmar_id>', methods=['GET'])
@token_required
def get_one_engmar(current_user, engmar_id):
    engmar = EnglishMarathi.query.filter_by(Key=engmar_id).first()

    if not engmar:
        return jsonify({'message' : 'No word found!'})

    engmar_data = {}
    engmar_data['Key'] = engmar.Key
    engmar_data['Meaning1'] = engmar.Meaning1
    engmar_data['Meaning2'] = engmar.Meaning2
    engmar_data['Meaning3'] = engmar.Meaning3
    engmar_data['Meaning4'] = engmar.Meaning4

    return jsonify(engmar_data)

@app.route('/engmar', methods=['POST'])
@token_required
def create_engmar(current_user):
    data = request.get_json()

    new_engmar = EnglishMarathi(Key=data['Key'], Meaning1=data['Meaning1'], Meaning2=data['Meaning2'], Meaning3=data['Meaning3'], Meaning4=data['Meaning4'])
    db.session.add(new_engmar)
    db.session.commit()

    return jsonify({'message' : "New word Inserted!"})

# @app.route('/engmar/<engmar_id>', methods=['PUT'])
# @token_required
# def complete_engmar(current_user, engmar_id):
#     engmar = EnglishMarathi.query.filter_by(Key=engmar_id).first()
#     data = request.get_json()

#     if not engmar:
#         return jsonify({'message' : 'No word found!'})

#     updated_engmar = EnglishMarathi(Key=data['Key'], Meaning1=data['Meaning1'], Meaning2=data['Meaning2'], Meaning3=data['Meaning3'], Meaning4=data['Meaning4'])
#     db.session.add(updated_engmar)
#     db.session.commit()

#     return jsonify({'message' : 'word and meaning successfuly updated!'})

@app.route('/engmar/<engmar_id>', methods=['DELETE'])
@token_required
def delete_engmar(current_user, engmar_id):
    engmar = EnglishMarathi.query.filter_by(Key=engmar_id).first()

    if not engmar:
        return jsonify({'message' : 'No word found!'})

    db.session.delete(engmar)
    db.session.commit()

    return jsonify({'message' : 'word deleted!'})

if __name__ == '__main__':
    app.run(host='marathidictionaryapi.heroku.com', debug=False)