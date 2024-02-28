from flask import Flask, render_template, request, redirect, flash, url_for, session
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
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")
        user_filter = users.find_one({"email":email})
        try:
            hashed_password = user_filter["password"]
        except TypeError:
            flash("Invalid Username or Password", "error")
            return redirect(url_for("login"))
        if user_filter and bcrypt.check_password_hash(hashed_password, password):
            session["user"] = email
            flash("Login Successful. Hi, Kevin", "success")
            return redirect(url_for("home"))
        flash("Invalid Username or Password", "error")
        return redirect(url_for("login"))
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

@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("Logged Out!", "error")
    return redirect(url_for("login"))

if __name__ == "__main__":
    app.run(debug=True)