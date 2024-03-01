from flask import Flask, request, session
from flask_restful import Resource, Api, reqparse, abort
from pymongo import MongoClient, ReturnDocument
from flask_bcrypt import Bcrypt
import array


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
register_args.add_argument("library", type=list, help="User's library")
register_args.add_argument("dictionary", type=list, help="User's dictionary")

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



# Arguments required for history
history_args = reqparse.RequestParser()
history_args.add_argument("id", type=str, help="History id", required=True)
history_args.add_argument("title", type=str, help="Word history title", required=True)
history_args.add_argument("definition", type=str, help="word definition", required=True)
history_args.add_argument("example", type=str, help="word example", required=True)
history_args.add_argument("source", type=dict, help="word source", required=True)


# Get Book Arguments
get_book_args = reqparse.RequestParser()
get_book_args.add_argument("book_id_list", type=list, help="Booklist", required=True)

# MongoDB client
connection_string = f"""mongodb+srv://intelib:intelib_api@intelib-api.hp3gykf.mongodb.net/?retryWrites=true&w=majority&appName=intelib-api"""

client = MongoClient(connection_string)

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
        # Two users can't use the same email
        if users.find_one({"email":user["email"]}):
            return abort("User with this email already exists")
        hashed_password = bcrypt.generate_password_hash(user["password"]).decode('utf-8')
        user["password"] = hashed_password
        user["_id"] = f"{user['first_name'].lower()}_{user['last_name'].lower()}"
        users.insert_one(dict(user))
        return user, 201


# Save book in user's library. Returns user with updated library
class SaveBook(Resource):
    def post(self, email):
        book = book_args.parse_args()
        user = users.find_one({"email": email})
        library = user["library"]
        if library:
            if book["id"] in library:
                return abort(409, messsage="Book already exists in user library")
            library.append(book["id"])
        else:
            library = [book["id"]]
        user = users.find_one_and_update({"email": email}, 
                                                 {"$set": {"library": library}}, 
                                                 return_document=ReturnDocument.AFTER)
        book["_id"] = book["id"]
        del book["id"]
        books.insert_one(book)
        return user, 201
    
class AddWord(Resource):
    def post(self, email):
        history_arguments = history_args.parse_args()
        user = users.find_one({"email": email})
        dictionary = user["dictionary"]
        if dictionary:
            if history_arguments["id"] in dictionary:
                return abort(409, message="word already exists in user dictionary")
            dictionary.append(history_arguments["id"])
        else:
            dictionary = [history_arguments["id"]]
        user = users.find_one_and_update({"email": email}, 
                                                 {"$set": {"dictionary": dictionary}}, 
                                                 return_document=ReturnDocument.AFTER)
        history_arguments["_id"] = history_arguments["id"]
        del history_arguments["id"]
        history.insert_one(history_arguments)
        return user, 201

# Endpoint to get book from DB. Takes a list of book IDs as a parameter and returns a list of books
class GetBooks(Resource):
    def get(self):
        # Check if parameter is supplied 
        if request.json is None:
            return abort(400, message="You need to supply a list of book IDs: {'book_id_list': ['book_id1', 'book_id2']}")
        book_id_list = request.json["book_id_list"]
        # Check to make sure all book IDs are valid
        for book_id in book_id_list:
            if books.find_one({"_id": book_id}) is None:
                return abort(400, message=f"'{book_id}' is an invalid Book ID")
        query = {"_id": {"$in": book_id_list}}
        books_returned = list(books.find(query))
        return books_returned

# Endpoint to get word from DB. Takes a list of word IDs as a parameter and returns a list of words
class GetWords(Resource):
    def get(self):
        # Check if parameter is supplied 
        if request.json is None:
            return abort(400, message="You need to supply a list of word IDs: {'word_id_list': ['word_id1', 'word_id2']}")
        word_id_list = request.json["word_id_list"]
        # Check to make sure all word IDs are valid
        for word_id in word_id_list:
            if history.find_one({"_id": word_id}) is None:
                return abort(400, message=f"'{word_id}' is an invalid Book ID")
        query = {"_id": {"$in": word_id_list}}
        words_returned = list(history.find(query))
        return words_returned

# Endpoint to get all users. Returns all users
class GetAllUsers(Resource):
    def get(self):
        user_list = {}
        counter = 1
        for user in users.find({}):
            user_list[counter] = user
            counter += 1
        return user_list

# Endpoint to delete a book from the user's library. Returns user with updated library
class DeleteBookFromUser(Resource):
    def delete(self, book_id, email):
        # Finds and deletes book from books' document
        book = books.find_one_and_delete({"_id": book_id})
        user = users.find_one({"email": email})
        # Check if parameters supplied are valid
        if book is None:
            return abort("Invalid book id")
        elif user is None:
            return abort("Invalid email")
        library = user["library"]
        library.remove(book_id)
        user = users.find_one_and_update({"email": email}, 
                                                 {"$set": {"library": library}}, 
                                                 return_document=ReturnDocument.AFTER)
        return user


# Endpoint to get one user. Return specific user
class GetOneUser(Resource):
    def get(self, email):
        user = users.find_one({"email": email})
        if user:
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
api.add_resource(SaveBook, "/save_book/<email>")
api.add_resource(GetAllUsers, "/get_all_users")
api.add_resource(GetOneUser, "/get_one_user/<email>")
api.add_resource(UpdateUser, "/update_user/<email>")
api.add_resource(DeleteUser, "/delete_user/<email>")
api.add_resource(DeleteBookFromUser, "/delete_book/<book_id>/<email>")
api.add_resource(GetBooks, "/get_books")
api.add_resource(GetWords, "/get_words")
api.add_resource(AddWord, "/add_word/<email>")
api.add_resource(Login, "/login")
api.add_resource(Logout, "/logout")

if __name__ == "__main__":
    app.run(debug=True)
