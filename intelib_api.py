from flask import Flask, abort, session
from flask_restful import Resource, Api, reqparse
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
import json


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
register_args.add_argument("phone_number", type=int, help="User's phone number", required=True)
register_args.add_argument("about_your_job", type=str, help="User's job description")
register_args.add_argument("about_your_family", type=str, help="User's family description")
register_args.add_argument("about_your_neighborhood", type=str, help="User's neighborhood description")
register_args.add_argument("about_your_hobbies", type=str, help="User's hobbies")
register_args.add_argument("about_your_personality", type=str, help="User's personality description")


# Arguments requires to log a user in
login_args = reqparse.RequestParser()
login_args.add_argument("email", type=str, help="User's email", required=True)
login_args.add_argument("password", type=str, help="User's password", required=True)

# MongoDB client
client = MongoClient("localhost", 27017)

# DB Initilization
db = client.flask_database
users = db.users
auth_json_file = open("intelib_google_auth.json")
google_auth_json = json.load(auth_json_file)["web"]


# Base endpoint
class HelloWorld(Resource):
    def get(self):
        return {"Api":"Works!"}

# Register user endpoint
class Register(Resource):
    def post(self):
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

# Logout endpoint
class Logout(Resource):
    def get(self):
        session.clear()
        return {"user": "Logged out!"}
    
    
# Endpoint URLs
api.add_resource(HelloWorld, "/")
api.add_resource(Register, "/register")
api.add_resource(GetAllUsers, "/get_all_users")
api.add_resource(GetOneUser, "/get_one_user/<email>")
api.add_resource(Logout, "/logout")

if __name__ == "__main__":
    app.run(debug=True)
