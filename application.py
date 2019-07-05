import os
import re
from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
@app.after_request
def after_request(response):
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.route("/")
@login_required
def index():
    quote = lookup(request.form.get("symbol"))
    
    return apology("TODO")


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "POST":
        if request.form.get("symbol") == None:
            return apology("Provide a stock.")
        else:
            quote = lookup(request.form.get("symbol"))
            if quote == None:
                return apology("This is not a stock.")
        if request.form.get("shares") == None:
            return apology("Tell us your shares.")
        else:
            shares = request.form.get("shares")
            cash = db.execute("SELECT cash FROM users WHERE id = :id", id = session["user_id"])[0]["cash"]
            if quote["price"]*float(shares) < 0 or quote["price"]*float(shares) > cash or quote["price"]*float(shares) == 0:
                return apology("This number is too low or is higher than the amount of cash you have. So we can not complete the transaction.")
            left = cash - quote["price"]*float(shares)
            return db.execute("UPDATE cash SET left WHERE left = :left")
            return db.execute("SELECT left FROM cash")
            return render_template("index.html")
    else:
        return render_template("buy.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""
    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/login")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "POST":
        if request.form.get("symbol") == None:
            return apology("Please provide a company.")
        
        else:
            quote=lookup(request.form.get("symbol"))
            if quote == None:
                return apology("This is not a stock.")
            return render_template("quoted.html", quote=quote)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        password = request.form.get("password")
        if request.form.get("username") == None:
            return apology("Sorry your username is blank. Please input a valid username.")
        if password != request.form.get("confirmation") or password == None or password == request.form.get("username"):
            return apology("Your passwords do not match, you need a password to continue, or your password is the same as your username. Please match the passwords or create a valid password.")
        while True:
            if re.search('[0-9]', password) is None:
                return apology("Your password needs at least one number.")
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))
        if not rows:
            db.execute("INSERT INTO users(username, hash) VALUES(:username, :password_hash)", username=request.form.get("username"), password_hash=generate_password_hash(request.form.get("password")))
            return redirect("/")
        else:
            return apology("This username is taken.")
    else:
        return render_template("register.html")
@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method("POST"):
        if request.form.get("symbol") == None:
            return apology("Provide a stock.")
        else:
            quote = lookup(request.form.get("symbol"))
            if quote == None:
                return apology("This is not a stock.")
        if request.form.get("shares") == None:
            return apology("Tell us your shares.")
        else:
            shares = request.form.get("shares")
            cash = db.execute("SELECT cash FROM users WHERE id = :id", id = session["user_id"])[0]["cash"]
            if quote["price"]*float(shares) < 0 or quote["price"]*float(shares) == 0:
                return apology("This number is too low. We can not sell this amount.")
    else:
        return render_template("sell.html")
def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
