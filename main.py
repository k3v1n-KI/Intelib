from flask import Flask, render_template, request, redirect, flash, url_for
from pymongo import MongoClient
from flask_bcrypt import Bcrypt



app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = "Something Omnius"

client = MongoClient("localhost", 27017)

db = client.flask_database
users = db.users


@app.route("/")
def home():
    return render_template("index.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    return render_template("login.html")


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

if __name__ == "__main__":
    app.run(debug=True)