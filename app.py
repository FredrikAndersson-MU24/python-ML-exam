import flask
import numpy as np
import joblib
import datetime
import re
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

model_path = 'ML_model/diabetes_random_forest_classifier.joblib'
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

    def __init__(self, user_id, result, type):
        global next_prediction_id
        next_prediction_id += 1
        self._prediction_id = next_prediction_id
        self._created = datetime.datetime.now()
        self._user_id = user_id
        self._result = result
        self._type = type

    def get_prediction_id(self):
        return self._prediction_id

    def get_user_id(self):
        return f"{self._user_id}"

    def get_result(self):
        return f"{self._result}"

    def get_created(self):
        return f"{self._created}"

    def get_type(self):
        return f"{self._type}"


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


def username_exists(username):
    for user in users:
        if user.get_username().lower() == username.lower():
            return True
    return False


def valid_username(username):
    if username is None or len(username) < 8 or len(username) > 32:
        return False
    return True


def valid_password(password):
    if password is None or len(password) < 8 or len(password) > 32:
        return None
    reg = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$#%])[A-Za-z\d@$#%]{8,32}$"
    pattern = re.compile(reg)
    match_pattern = re.search(pattern, password)
    return match_pattern

def validate_request_parameters(data):
    errors =[]
    gen_hlth = data.get("gen_hlth")
    if gen_hlth is None or gen_hlth < 1 or gen_hlth > 5:
        errors.append("gen_hlth must be between 1 and 5")
    high_bp = data.get("high_bp")
    if high_bp is None or high_bp != 0 and high_bp != 1:
        errors.append("high_bp must be 0 if false or 1 if true")
    bmi = data.get("bmi")
    if bmi is None or bmi < 1 or bmi > 100:
        errors.append("bmi must be between 1 and 100")
    high_chol = data.get("high_chol")
    if high_chol is None or high_chol != 0 and high_chol != 1:
        errors.append("high_chol must be 0 if false or 1 if true")
    age = data.get("age")
    if age is None or age < 1 or age > 13:
        errors.append("age must be between 1 and 13")
    diff_walk = data.get("diff_walk")
    if diff_walk is None or diff_walk != 0 and diff_walk != 1:
        errors.append("diff_walk must be 0 if false or 1 if true")
    phys_hlth = data.get("phys_hlth")
    if phys_hlth is None or phys_hlth < 0 or phys_hlth > 30:
        errors.append("phys_hlth must be between 0 and 30")
    heart_disease_or_attack = data.get("heart_disease_or_attack")
    if heart_disease_or_attack is None or heart_disease_or_attack != 0 and heart_disease_or_attack != 1:
        errors.append(("heart_disease_or_attack must be 0 if false or 1 if true"))
    phys_activity = data.get("phys_activity")
    if phys_activity is None or phys_activity != 0 and phys_activity != 1:
        errors.append(("phys_activity must be 0 if false or 1 if true"))
    education = data.get("education")
    if education is None or education < 1 or education > 6:
        errors.append(("education must be between 1 and 6"))
    income = data.get("income")
    if income is None or income < 1 or income > 8:
        errors.append(("income must be between 1 and 8"))
    return errors


def get_top_contributors(model, feature_values, feature_names, top_n=3):
    """
    Calculate top contributing features to the prediction.
    Returns list of tuples: (feature_name, importance_value)
    """
    if hasattr(model, 'feature_importances_'):
        # For tree-based models, multiply feature importance by feature value
        importances = model.feature_importances_
        contributions = importances * np.abs(feature_values[0])

        # Get indices of top contributors
        top_indices = np.argsort(contributions)[-top_n:][::-1]

        return [(feature_names[i], round(float(contributions[i]), 4))
                for i in top_indices]
    else:
        return []

# Authenticate
# Register


@app.route('/api/auth/register', methods=['POST'])
def register():
    username = request.json.get("username")
    password = request.json.get("password")
    if username_exists(username):
        return jsonify({"error": "username already exists"}), 400
    elif not valid_username(username):
        return jsonify({"error": "username must be 8-32 characters"}), 400
    if not valid_password(password):
        return jsonify({"error": "password must be 8-32 characters and contain at least one uppercase letter, one lowercase letter, one number, and one special character"}), 400
    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    new_user = User(username, hashed_password)
    users.append(new_user)
    return jsonify({"message": "User added successfully"}), 201

# Login


@app.route('/api/auth/login', methods=['POST'])
def login():
    username = request.json.get("username")
    password = request.json.get("password")
    if not username_exists(username):
        return jsonify({"error": "username does not exist"}), 400
    stored_hashed_password = get_stored_password_by_username(username)
    if not bcrypt.check_password_hash(stored_hashed_password, password):
        return jsonify({"error": "incorrect password"}, 400)
    access_token = create_access_token(identity=username)
    return jsonify(access_token=access_token)

# Predict
# Create


@app.route('/api/predict/classification', methods=['POST'])
@jwt_required()
def predict_classification():
    global current_user
    global predictions
    current_user = get_jwt_identity()
    user_id = get_user_id_by_user(current_user)
    data = request.json
    errors = validate_request_parameters(data)
    if len(errors) > 0:
        return flask.jsonify({"errors": errors}), 400
    features = np.array([[
        data.get("gen_hlth"),
        data.get("high_bp"),
        data.get("bmi"),
        data.get("high_chol"),
        data.get("age"),
        data.get("diff_walk"),
        data.get("phys_hlth"),
        data.get("heart_disease_or_attack"),
        data.get("phys_activity"),
        data.get("education"),
        data.get("income")]])
    predict = loaded_model.predict(features)
    classification = Prediction(user_id, int(predict[0]), "classification")
    predictions.append(classification)
    return flask.jsonify({"prediction_id": classification.get_prediction_id(),
                          "type": classification.get_type(),
                          "result": classification.get_result(),
                          "user_id": classification.get_user_id()})


@app.route('/api/predict/probability', methods=['POST'])
@jwt_required()
def predict_probability():
    global current_user
    global predictions
    current_user = get_jwt_identity()
    user_id = get_user_id_by_user(current_user)
    data = request.json
    errors = validate_request_parameters(data)
    if len(errors) > 0:
        return flask.jsonify({"errors": errors}), 400

    features = np.array([[
        data.get("gen_hlth"),
        data.get("high_bp"),
        data.get("bmi"),
        data.get("high_chol"),
        data.get("age"),
        data.get("diff_walk"),
        data.get("phys_hlth"),
        data.get("heart_disease_or_attack"),
        data.get("phys_activity"),
        data.get("education"),
        data.get("income")]])
    predict = loaded_model.predict_proba(features)[:,1][0]
    probability = Prediction(user_id, round((predict * 100), 2), "probability")
    predictions.append(probability)
    return flask.jsonify({"prediction_id": probability.get_prediction_id(),
                          "type": probability.get_type(),
                          "result": probability.get_result(),
                          "user_id": probability.get_user_id()})

# Read
@app.route('/api/predict', methods=['GET'])
def get_predictions():
    predictions_list = []
    for prediction in predictions:
        predictions_list.append({
            "prediction_id": prediction.get_prediction_id(),
            "type": prediction.get_type(),
            "result": prediction.get_result(),
            "user_id": prediction.get_user_id(),
            "created": prediction.get_created()})
    return jsonify({"predictions": predictions_list}), 200


if __name__ == '__main__':
    app.run(debug=True)
