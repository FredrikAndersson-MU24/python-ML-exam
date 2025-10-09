import numpy as np
import joblib
from flask_jwt_extended import create_access_token, JWTManager, jwt_required, get_jwt_identity
from flask_bcrypt import Bcrypt, jsonify, request
from flask import Flask

app = Flask(__name__)
users = []
predictions = []
next_user_id = 2
next_post_id = 2
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

prediction = np.array(
    [[3, 1, 26, 0, 4, 0, 30, 0, 1, 6, 8],
     [3, 1, 26, 1, 12, 0, 0, 0, 0, 6, 8],
     [1, 0, 26, 0, 13, 0, 10, 0, 1, 6, 8]])

predict = loaded_model.predict(prediction)


print(predict)


class User():
    def __init__(self, username, password, email):
        global next_user_id
        next_user_id += 1
        self._user_id = next_user_id
        self._username = username
        self._password = password
        self._email = email

    def get_user_id(self):
        return self._user_id

    def get_username(self):
        return self._username

    def get_password(self):
        return self._password

    def print_user(self):
        print(f"{self._user_id}, {self._username}, {self._password}, {self._email}")


class Post():
    def __init__(self, user_id, title, body):
        global next_post_id
        next_post_id += 1
        self._post_id = next_post_id
        self._user_id = user_id
        self._title = title
        self._body = body
        self._comments = []

    def get_post_id(self):
        return f"{self._post_id}"

    def get_user_id(self):
        return f"{self._user_id}"

    def get_title(self):
        return f"{self._title}"

    def get_body(self):
        return f"{self._body}"

    def get_comments(self):
        return self._comments

    def get_post(self):
        return f"Title: {self._title}, Body: {self._body}, Author: {self._user_id}"

    def print_post(self):
        return jsonify({"Title": self._title, "Body": self._body, "Author": self._user_id})

    @property
    def comments(self):
        return self._comments

    @comments.setter
    def comments(self, comments):
        self._comments = comments


class Comment():
    def __init__(self, user_id, post_id, body):
        global next_comment_id
        next_comment_id += 1
        self._comment_id = next_comment_id
        self._post_id = post_id
        self._user_id = user_id
        self._body = body

    def get_comment_id(self):
        return f"{self._comment_id}"

    def get_post_id(self):
        return f"{self._post_id}"

    def get_user_id(self):
        return f"{self.user_id}"

    def get_body(self):
        return f"{self._body}"


current_user = User(None, None, None)
liz = User(
    "liz", "$2b$12$v1/77VLBqAg9dz7tiXF70uzIr0PitZE/mDHIvgbTgh8uGCrXMFYFa", "liz@ned.ned")
ned = User(
    "ned", "$2b$12$T8d3jzvj48f19U2ywHogX.yDWcV3aob5PLYZsB6foieav.SUAnrwi", "ned@ned.ned")
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


def find_post_by_id(post_id):
    for post in posts:
        if post.get_post_id() == post_id:
            return post


def update_comments(post, new_comment):
    updated_comments = post.get_comments()
    updated_comments.append(new_comment)
    post.comments = updated_comments

# USER
# Register


@app.route('/api/auth/register', methods=['POST'])
def user_register():
    username = request.json.get("username")
    password = request.json.get("password")
    email = request.json.get("email")
    hashed_password = bcrypt.generate_password_hash(password).decode("utf-8")
    new_user = User(username, hashed_password, email)
    users.append(new_user)
    get_all_users()
    return jsonify({"message": "User added succesfully"}, 201)

# Login


@app.route('/api/auth/login', methods=['POST'])
def user_login():
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
def post_create():
    title = request.json.get("title")
    body = request.json.get("body")
    current_user = get_jwt_identity()
    user_id = get_user_id_by_user(current_user)
    new_post = Post(user_id, title, body)
    posts.append(new_post)
    return jsonify({"title": new_post.get_title(), "body": new_post.get_body(), "author": get_jwt_identity(), "user id": user_id}, 200)


# Read
@app.route('/api/predict', methods=['GET'])
def predictions_read():
    predictions_list = []
    for prediction in predictions:
        list_of_comments = []
        for comment in prediction.get_comments():
            list_of_comments.append({"body": comment.get_body()})
        predictions_list.append({
            "post_id": prediction.get_post_id(),
            "author_id": prediction.get_user_id(),
            "title": prediction.get_title(),
            "body": prediction.get_body(),
            "comments": list_of_comments})
    return jsonify({"posts": predictions_list}), 200


if __name__ == ('__main__'):
    app.run(debug=True)
