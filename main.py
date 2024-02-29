from flask import Flask, session
from flask_restful import Resource, Api, reqparse, abort
from pymongo import MongoClient, ReturnDocument
from flask_bcrypt import Bcrypt
import json


# Initilize Flask API
app = Flask(__name__)
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

# Arguments required to update a user's profile
update_args = reqparse.RequestParser()
update_args.add_argument("first_name", type=str, help="User's first name")
update_args.add_argument("last_name", type=str, help="User's last name")
update_args.add_argument("email", type=str, help="User's email")
update_args.add_argument("password", type=str, help="User's password")
update_args.add_argument("phone_number", type=int, help="User's phone number")
update_args.add_argument("about_your_job", type=str, help="User's job description")
update_args.add_argument("about_your_family", type=str, help="User's family description")
update_args.add_argument("about_your_neighborhood", type=str, help="User's neighborhood description")
update_args.add_argument("about_your_hobbies", type=str, help="User's hobbies")
update_args.add_argument("about_your_personality", type=str, help="User's personality description")


# Arguments required to log a user in
login_args = reqparse.RequestParser()
login_args.add_argument("email", type=str, help="User's email", required=True)
login_args.add_argument("password", type=str, help="User's password", required=True)

# Arguments required to store books
book_args = reqparse.RequestParser()
book_args.add_argument("id", type=str, help="Book id", required=True)
book_args.add_argument("title", type=str, help="Book title", required=True)
book_args.add_argument("last_page_read", type=int, help="Last page read", required=True)
book_args.add_argument("last_page_read_datetime", type=str, help="Last page read datetime", required=True)
book_args.add_argument("number_of_pages", type=int, help="Number of Pages", required=True)


# Arguments required for history
history_args = reqparse.RequestParser()
history_args.add_argument("id", type=str, help="History id", required=True)
history_args.add_argument("title", type=str, help="Word history title", required=True)
history_args.add_argument("definition", type=str, help="word definition", required=True)
history_args.add_argument("example", type=str, help="word example", required=True)
history_args.add_argument("source", type=dict, help="word source", required=True)


# MongoDB client
client = MongoClient("localhost", 27017)

# DB Initilization
db = client.flask_database
users = db.users
books = db.books
history = db.history



# Base endpoint
class HelloWorld(Resource):
    def get(self):
        return {"Api":"Works!"}

# Register user endpoint. Returns Registered user
class Register(Resource):
    def post(self):
        user = register_args.parse_args()
        hashed_password = bcrypt.generate_password_hash(user["password"]).decode('utf-8')
        user["password"] = hashed_password
        users.insert_one(dict(user))
        return user, 201


# Save book in library. Returns saved book
class SaveBoook(Resource):
    def post(self):
        book = book_args.parse_args()
        books.insert_one(dict(book))
        return book, 201

# Endpoint to get all users. Returns all users
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

# Endpoint to get all books. Returns all books
class GetAllBooks(Resource):
    def get(self, email=None):
        if email is None:
            library = {}
            counter = 1
            for book in books.find({}):
                book = dict(book)
                del book["_id"]
                library[counter] = book
                counter += 1
            return library
        else:
            pass

# Endpoint to get one user. Return specific user
class GetOneUser(Resource):
    def get(self, email):
        user = users.find_one({"email": email})
        if user:
            user = dict(user)
            del user["_id"]
            return user
        return abort("User email is Invalid")

# Update user endpoint. Returns Updated User
class UpdateUser(Resource):
    def put(self, email):
        # Columns that are nullable
        nullable_fields = ["about_your_job", "about_your_family", "about_your_neighborhood", 
                           "about_your_hobbies", "about_your_personality"]
        # Update arguments 
        args_for_update = dict(update_args.parse_args())
        # Removing all null attributes to only update the fields that needs to be updated.
        # Attributes in the "nullable_fields" list can be Null
        filtered_update_args = {key: value for key, value in args_for_update.items() \
                                if value is not None or key in nullable_fields}
        # If password is being updated, we hash it before sending it to the database
        if "password" in filtered_update_args.keys():
            hashed_password = bcrypt.generate_password_hash(filtered_update_args["password"]).decode('utf-8')
            filtered_update_args["password"] = hashed_password
        # Update user and return updated user
        user = users.find_one_and_update(
            {"email": email}, 
            { '$set': filtered_update_args }, 
            return_document = ReturnDocument.AFTER
            )
        # Throw an error if email is invalid
        if user is None:
            return abort("User email is invalid")
        user = dict(user)
        del user["_id"]
        return user
    
# Delete user endpoint. Returns deleted user
class DeleteUser(Resource):
    def delete(self, email):
        user = users.find_one_and_delete({"email": email})
        # Throws an error if user is invalid
        if user is None:
            return abort("User email is invalid")
        user = dict(user)
        del user["_id"]
        return user
        
    
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
            return abort("Invalid Username or Password")
        
        # Match Password hash
        if user and bcrypt.check_password_hash(hashed_password, password):
            user = dict(user)
            del user["_id"]
            return user
        # Return Bad request because of invalid credentials
        return abort("Invalid Username or Password")

# Logout endpoint
class Logout(Resource):
    def get(self):
        session.clear()
        return {"user": "Logged out!"}
    
    
# Endpoint URLs
api.add_resource(HelloWorld, "/")
api.add_resource(Register, "/register")
api.add_resource(SaveBoook, "/save_book")
api.add_resource(GetAllUsers, "/get_all_users")
api.add_resource(GetOneUser, "/get_one_user/<email>")
api.add_resource(UpdateUser, "/update_user/<email>")
api.add_resource(DeleteUser, "/delete_user/<email>")
api.add_resource(Login, "/login")
api.add_resource(Logout, "/logout")

if __name__ == "__main__":
    app.run(debug=True)
