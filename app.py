import flask
import numpy as np
import joblib
import datetime
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt
from flask import Flask, jsonify, request

app = Flask(__name__)
users = []
predictions = []
next_user_id = 2
next_prediction_id = 2

app.config["JWT_SECRET_KEY"] = "my_not_so_secret_key"
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
auth = ""

model_path = 'ML_model/diabetes_random_forest_classifier_model.joblib'
try:
    loaded_model = joblib.load(model_path)
    print("Model loaded successfully")
except FileNotFoundError as err:
    print(f"Error loading model: {err}")

class User:
    def __init__(self, username, password):
        global next_user_id
        next_user_id += 1
        self._user_id = next_user_id
        self._username = username
        self._password = password

    def get_user_id(self):
        return self._user_id

    def get_username(self):
        return self._username

    def get_password(self):
        return self._password

    def print_user(self):
        print(f"{self._user_id}, {self._username}, {self._password}")

class Prediction:

    def __init__(self, user_id, prediction):
        global next_prediction_id
        next_prediction_id += 1
        self._prediction_id = next_prediction_id
        self._created = datetime.datetime.now()
        self._user_id = user_id
        self._prediction = prediction

    def get_prediction_id(self):
        return self._prediction_id

    def get_user_id(self):
        return f"{self._user_id}"

    def get_prediction(self):
        return f"{self._prediction}"

    def get_created(self):
        return f"{self._created}"

current_user = User(None, None)
liz = User(
    "liz", "liz")
ned = User(
    "ned", "ned")
users.append(liz)
users.append(ned)

def get_all_users():
    global users
    for user in users:
        user.print_user()

def get_stored_password_by_username(username):
    for user in users:
        if user.get_username() == username:
            return user.get_password()


def get_user_id_by_user(username):
    for user in users:
        if user.get_username() == username:
            return user.get_user_id()

def check_if_user_exists(username):
    for user in users:
        if user.get_username().lower() == username.lower():
            return None
    return username

# USER
# Register

@app.route('/api/auth/register', methods=['POST'])
def register():
    username = check_if_user_exists(request.json.get("username"))
    if username is None:
        return jsonify({"error": "username already exists"}), 400
    if len(username) < 8 or len(username) > 32:
        return jsonify({"error": "username must be 8-32 characters"}), 400
    password = request.json.get("password")
    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    new_user = User(username, hashed_password)
    users.append(new_user)
    return jsonify({"message": "User added successfully"}), 201

# Login

@app.route('/api/auth/login', methods=['POST'])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    stored_hashed_password = get_stored_password_by_username(username)
    if not bcrypt.check_password_hash(stored_hashed_password, password):
        return jsonify({"error": "incorrect password"}, 400)
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

# POSTS
# Create

@app.route('/api/predict', methods=['POST'])
@jwt_required()
def new_prediction():
    global current_user
    global predictions
    errors =[]
    current_user = get_jwt_identity()
    user_id = get_user_id_by_user(current_user)
    gen_hlth = request.json.get("gen_hlth")
    if gen_hlth is None or gen_hlth < 1 or gen_hlth > 5:
        errors.append("gen_hlth must be between 1 and 5")
    high_bp = request.json.get("high_bp")
    if high_bp is None or high_bp != 0 and high_bp != 1:
        errors.append("high_bp must be 0 if false or 1 if true")
    bmi = request.json.get("bmi")
    if bmi is None or bmi < 1 or bmi > 50:
        errors.append("bmi must be between 1 and 50")
    high_chol = request.json.get("high_chol")
    if high_chol is None or high_chol != 0 and high_chol != 1:
        errors.append("high_chol must be 0 if false or 1 if true")
    age = request.json.get("age")
    if age is None or age < 1 or age > 13:
        errors.append("age must be between 1 and 13")
    diff_walk = request.json.get("diff_walk")
    if diff_walk is None or diff_walk != 0 and diff_walk != 1:
        errors.append("diff_walk must be 0 if false or 1 if true")
    phys_hlth = request.json.get("phys_hlth")
    if phys_hlth is None or phys_hlth < 0 or phys_hlth > 30:
        errors.append("phys_hlth must be between 0 and 30")
    heart_disease_or_attack = request.json.get("heart_disease_or_attack")
    if heart_disease_or_attack is None or heart_disease_or_attack != 0 and heart_disease_or_attack != 1:
        errors.append(("heart_disease_or_attack must be 0 if false or 1 if true"))
    phys_activity = request.json.get("phys_activity")
    if phys_activity is None or phys_activity != 0 and phys_activity != 1:
        errors.append(("phys_activity must be 0 if false or 1 if true"))
    education = request.json.get("education")
    if education is None or education < 1 or education > 6:
        errors.append(("education must be between 1 and 6"))
    income = request.json.get("income")
    if income is None or income < 1 or income > 8:
        errors.append(("income must be between 1 and 8"))

    if len(errors) > 0:
        return flask.jsonify({"errors": errors}), 400

    prediction = loaded_model.predict(np.array([[gen_hlth,
                                      high_bp,
                                      bmi,
                                      high_chol,
                                      age,
                                      diff_walk,
                                      phys_hlth,
                                      heart_disease_or_attack,
                                      phys_activity,
                                      education,
                                      income]]))
    new_prediction = Prediction(user_id, int(prediction[0]))
    predictions.append(new_prediction)
    return flask.jsonify({"prediction_id": new_prediction.get_prediction_id(),
                          "prediction": new_prediction.get_prediction(),
                          "user_id": new_prediction.get_user_id()})

# Read
@app.route('/api/predict', methods=['GET'])
def get_predictions():
    predictions_list = []
    for prediction in predictions:
        predictions_list.append({
            "prediction_id": prediction.get_prediction_id(),
            "prediction": int(prediction.get_prediction()),
            "user_id": prediction.get_user_id(),
            "created": prediction.get_created()})
    return jsonify({"predictions": predictions_list}), 200


if __name__ == '__main__':
    app.run(debug=True)
