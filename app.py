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
next_comment_id = 2

app.config["JWT_SECRET_KEY"] = "my_secret_key"
jwt = JWTManager(app)
bcrypt = Bcrypt(app)
auth = ""

model_path = './ML_model/diabetes_classification_model.joblib'
try:
    loaded_model = joblib.load(model_path)
    print("Model loaded successfully")
except FileNotFoundError as err:
    print(f"Error loading model: {err}")

# 'GenHlth', 'HighBP', 'BMI', 'HighChol', 'Age', 'DiffWalk', 'PhysHlth', 'HeartDiseaseorAttack', 'PhysActivity', 'Education','Income'

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

# USER
# Register


@app.route('/api/auth/register', methods=['POST'])
def register():
    username = request.json.get("username")
    password = request.json.get("password")
    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    new_user = User(username, hashed_password)
    users.append(new_user)
    get_all_users()
    return jsonify({"message": "User added successfully"}, 201)

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
    current_user = get_jwt_identity()
    user_id = get_user_id_by_user(current_user)
    gen_hlth = request.json.get("gen_hlth")
    high_bp = request.json.get("high_bp")
    bmi = request.json.get("bmi")
    high_chol = request.json.get("high_chol")
    age = request.json.get("age")
    diff_walk = request.json.get("diff_walk")
    phys_hlth = request.json.get("phys_hlth")
    heart_disease_or_attack = request.json.get("heart_disease_or_attack")
    phys_activity = request.json.get("phys_activity")
    education = request.json.get("education")
    income = request.json.get("income")

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
    print(prediction)
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
            "prediction": prediction.get_prediction(),
            "user_id": prediction.get_user_id()})
    return jsonify({"predictions": predictions_list}), 200


if __name__ == '__main__':
    app.run(debug=True)
