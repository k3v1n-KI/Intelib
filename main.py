from flask import Flask, render_template
from pymongo import MongoClient



app = Flask(__name__)
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
    return render_template("register.html")

if __name__ == "__main__":
    app.run(debug=True)