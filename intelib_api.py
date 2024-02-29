import os
import pathlib
import requests
from flask import Flask, request, redirect, flash, url_for, session, abort
from flask_restful import Resource, Api, reqparse
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
import json
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
from pip._vendor import cachecontrol

# Initilize Flask API
app = Flask("REST_API")
api = Api(app)
bcrypt = Bcrypt(app) # Hashing algorithm for passwords

# Arguments required to register a user
register_args = reqparse.RequestParser()
register_args.add_argument("first_name", type=str, help="User's first name", required=True)
register_args.add_argument("last_name", type=str, help="User's last name", required=True)
register_args.add_argument("email", type=str, help="User's email", required=True)
register_args.add_argument("password", type=str, help="User's password", required=True)
register_args.add_argument("phone_number", type=int, help="User's Phone Number", required=True)

# Arguments requires to log a user in
login_args = reqparse.RequestParser()
login_args.add_argument("email", type=str, help="User's email", required=True)
login_args.add_argument("password", type=str, help="User's password", required=True)

# MongoDB client
client = MongoClient("localhost", 27017)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" # to allow Http traffic for local dev

# DB Initilization
db = client.flask_database
users = db.users
auth_json_file = open("intelib_google_auth.json")
google_auth_json = json.load(auth_json_file)["web"]

# Google Credentials for Sign in
GOOGLE_CLIENT_ID = google_auth_json["client_id"]
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "intelib_google_auth.json")
app.secret_key = google_auth_json["client_secret"]

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

# Base endpoint
class HelloWorld(Resource):
    def get(self):
        return {"Api":"Works!"}

# Register user endpoint
class Register(Resource):
    def put(self):
        user = register_args.parse_args()
        hashed_password = bcrypt.generate_password_hash(user["password"]).decode('utf-8')
        user["password"] = hashed_password
        users.insert_one(dict(user))
        return user

# Endpoint to get all users
class GetAllUsers(Resource):
    def get(self):
        user_list = {}
        counter = 1
        for user in users.find({}):
            user = dict(user)
            del user["_id"]
            user_list[counter] = user
            counter += 1
        return user_list

# Endpoint to get one user
class GetOneUser(Resource):
    def get(self, email):
        user = users.find_one({"email": email})
        if user:
            user = dict(user)
            del user["_id"]
            return user
        return abort(404)

# Login Endpoint
class Login(Resource):
    def post(self):
        # Get Login Information
        args = login_args.parse_args()
        email = args.get("email")
        password = args.get("password")
        user = users.find_one({"email":email})
        
        # Generate password hash or return bad request if email isn't registered
        try:
            hashed_password = user["password"]
        except TypeError:
            return abort(400)
        
        # Match Password hash
        if user and bcrypt.check_password_hash(hashed_password, password):
            user = dict(user)
            del user["_id"]
            return user
        # Return Bad request because of invalid credentials
        return abort(400)

# Google login URL
@app.route("/google_auth_login")
def google_auth_login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    # Return user credentials that will be intercepted by the callback function
    return redirect(authorization_url)

# Google login callback
@app.route("/callback")
def callback():
    # Intercepts user credentials
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    # Gets ID token that will be used to access user data
    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    # Verifys token for security purposes
    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )
    # Add the user to session and stores their credentials in the database
    user = users.find_one({"email":id_info.get("email")})
    if user:
        del user["_id"]
    else:
        user = {
                "first_name": id_info.get("given_name"),
                "last_name": id_info.get("family_name"),
                "email": id_info.get("email"),
                "phone_number": None,
                "password": None
            }
        users.insert_one(user)
    return dict(user)

# Endpoint URLs
api.add_resource(HelloWorld, "/")
api.add_resource(Register, "/register")
api.add_resource(GetAllUsers, "/get_all_users")
api.add_resource(GetOneUser, "/get_one_user/<email>")
api.add_resource(Login, "/login")

if __name__ == "__main__":
    app.run(debug=True)
