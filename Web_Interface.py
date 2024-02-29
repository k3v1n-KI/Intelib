import os
import pathlib
import requests
from flask import Flask, render_template, request, redirect, flash, url_for, session, abort
from pymongo import MongoClient
from flask_bcrypt import Bcrypt
import json
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
import google.auth.transport.requests
from pip._vendor import cachecontrol


# Initialize Flask app. Add text encryptor for passwords
app = Flask(__name__)
bcrypt = Bcrypt(app)

# MongoDB client
client = MongoClient("localhost", 27017)
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1" # to allow Http traffic for local dev
# DB Initilization

db = client.flask_database
users = db.users
auth_json_file = open("intelib_google_auth.json")
google_auth_json = json.load(auth_json_file)["web"]
# Google Credentials for Signin
GOOGLE_CLIENT_ID = google_auth_json["client_id"]
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "intelib_google_auth.json")
app.secret_key = google_auth_json["client_secret"]

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)

# Chech if user is logged in
def login_is_required(function):
    def wrapper(*args, **kwargs):
        if "google_id" in session or "user" in session:
            return function()
        else:
            return abort(401)  # Authorization required

    return wrapper

@app.route("/")
@login_is_required
def home():
    return render_template("index.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        # Get Login Information
        email = request.form.get("email")
        password = request.form.get("password")
        user_filter = users.find_one({"email":email})
        try:
            hashed_password = user_filter["password"]
        except TypeError:
            flash("Invalid Username or Password", "error")
            return redirect(url_for("login"))
        # Match Password hash
        if user_filter and bcrypt.check_password_hash(hashed_password, password):
            session["user"] = email
            flash(f"Login Successful. Hi, {user_filter['first_name']}", "success")
            return redirect("/")
        # Flash error for invalid login credentials
        flash("Invalid Username or Password", "error")
        return redirect(url_for("login"))
    return render_template("login.html")

# Google Login
@app.route("/google_auth_login")
def google_auth_login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    # Return user credentials that will be intercepted by yhr callback function
    return redirect(authorization_url)

# Callback function
@app.route("/callback")
def callback():
    # Intercepts user credentials
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        print("DEBUGGING!!!!")
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
    session["google_id"] = id_info.get("sub")
    session["user"] = id_info.get("email")
    user_check = users.find_one({"email":session["user"]})
    if not user_check:
        users.insert_one({
                "first_name": id_info.get("given_name"),
                "last_name": id_info.get("family_name"),
                "email": id_info.get("email"),
                "phone_number": None,
                "password": None
            })
    flash(f"Login Successful. Hello, {id_info.get('given_name')}", "success")
    return redirect("/")

# manually registers the user and adds their credentials into the database
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        first_name = request.form.get("first_name")
        last_name = request.form.get("last_name")
        email = request.form.get("email")
        phone_number = request.form.get("phone_number")
        password = request.form.get("password")
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        users.insert_one({
            "first_name": first_name,
            "last_name": last_name,
            "email": email,
            "phone_number": phone_number,
            "password": hashed_password
        })
        flash(f"Your account has been successfully created, {first_name}", "success")
        return redirect(url_for("login"))
        
        
    return render_template("register.html")

# Clears session and logs the user out
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged Out!", "error")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)
