import os
import datetime
from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)
CORS(app)

app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY')
app.config['MONGO_DB_URI'] = os.getenv('MONGO_DB_URI')
app.config['FLASK_ENV'] = os.getenv('FLASK_ENV')

# MongoDB connection
client = MongoClient(app.config['MONGO_DB_URI'])
db = client.cluster0
users_collection = db.users

# JWT Configuration
jwt = JWTManager(app)

# Register route
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    if users_collection.find_one({"username": username}):
        return jsonify({"msg": "User already exists"}), 400

    hashed_password = generate_password_hash(password)
    users_collection.insert_one({"username": username, "password": hashed_password})

    return jsonify({"msg": "User registered successfully"}), 201

# Login route
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')

    user = users_collection.find_one({"username": username})
    if user and check_password_hash(user['password'], password):
        access_token = create_access_token(identity=username, expires_delta=datetime.timedelta(hours=1))
        return jsonify({"access_token": access_token}), 200

    return jsonify({"msg": "Invalid credentials"}), 401

# Protected route
@app.route('/protected', methods=['GET'])
@jwt_required()
def protected():
    current_user = get_jwt_identity()
    return jsonify({"logged_in_as": current_user}), 200

if __name__ == '__main__':
    app.run(debug=True)
