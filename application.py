import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd, check_positive_integer

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
app.config["SESSION_FILE_DIR"] = mkdtemp()
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
    """Show portfolio of stocks"""
    # Query cash amount
    cash = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])  # This returns rows of type dictionary
    cash = cash[0]["cash"]  # Save cash value in cash instead of dictionary
    portfolioTotal = cash   # make variable to count total of portfolio so we have pass it to index.html

    # Query portfolio(list of dictionary) content
    portfolio = db.execute("SELECT symbol,SUM(shares) FROM orders WHERE user_id=? GROUP BY symbol;", session["user_id"])
    portfolioNoZeroShares = []
    #print(portfolio)

    # Add stock name, share price and total (#share owned * price) to each stock so that we can pass it to the index.html
    for stock in portfolio: # each variable stock is a dictionary
        quote = lookup(stock["symbol"]) # quote is a dictionary with key name, price and symbol
        stock["name"] = quote["name"]
        stock["price"] = usd(quote["price"])
        stock["total"] = stock["SUM(shares)"] * quote["price"]
        portfolioTotal += stock["total"]    # summing the value of each stock in portfolio
        stock["total"] = usd(stock["total"])    # format to USD

        # if the share total is 0 then remove if from portfolio list
        if stock["SUM(shares)"] != 0:
            portfolioNoZeroShares.append(stock)

    #print(portfolio)
    return render_template("index.html", cash = usd(cash), portfolioTotal = usd(portfolioTotal), portfolio = portfolioNoZeroShares)


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        # When POST is requested
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Check if symbol is not blank
        if not symbol:
            return apology("must provide a symbol")

        # Check if shares is not blank:
        if not shares:
            return apology("must enter share quantity")

        # Check if shares is a positive integer
        if not check_positive_integer(shares):
            return apology("shares has to be a valid positive integer")
        shares = int(shares)

        # Check if symbol is valid (exist)
        stock = lookup(symbol)
        if stock != None:
            # Check how much cash the user have
            cash = db.execute("SELECT cash FROM users WHERE id=?", session["user_id"])  # This returns rows of type dictionary
            cash = cash[0]["cash"]  # Save cash value in cash instead of dictionary

            # User has enough cash
            if cash >= stock["price"] * shares:
                cash -= stock["price"] * shares     # User leftover cash
                db.execute("INSERT INTO orders (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)", session["user_id"], stock["symbol"], shares, stock["price"])      # Record purchase in db
                db.execute("UPDATE users SET cash=? WHERE id=?", cash, session["user_id"])# Update user cash in db
                flash("Buy sucessful!")
            # User does not have enough cash
            else:
                return apology("Not enough cash!")

            return redirect("/")

        # Symbol is not valid
        return apology("Symbol does not exist")
    else:
        # When GET is requested
        return render_template("buy.html")


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT symbol,shares,price,transacted FROM orders WHERE user_id=? ORDER BY transacted ASC", session["user_id"])

    # convert the price from float to USD string
    for row in history:
        row["price"] = usd(row["price"])

    return render_template("history.html", history=history)


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
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""
    if request.method == "POST":
        quote = lookup(request.form.get("symbol"))
        if quote == None:
            return apology("symbol does not exist")

        return render_template("quoted.html", stockName = quote["name"], stockSymbol = quote["symbol"], stockPrice = quote["price"])
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""
    # User is submitting form
    if request.method == "POST":

        # Check for empty username
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Check for empty password
        if not request.form.get("password"):
            return apology("must provide password", 403)

        # Check for empty password again
        if not request.form.get("confirmation"):
            return apology("must provide password (again)", 403)

        # Check password = password again
        if request.form.get("password") != request.form.get("confirmation"):
            return apology("password does not match", 403)

        # Check if username exist in database
        checkUsername = db.execute("SELECT username FROM users WHERE username = ?", request.form.get("username"))

        if not checkUsername:
            # Forget any user_id
            session.clear()

            # Hashing password
            hashPassword = generate_password_hash(request.form.get("password"))

            # Inserting new username and password to db
            userID = db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", request.form.get("username"), hashPassword)

            # Remember which user has logged in
            session["user_id"] = userID

            # Redirect user to home page
            flash('You are registered!')
            return redirect("/")
        else:
            return apology("username already exist", 403)
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    # Get list of stock symbol user owned
    portfolio = db.execute("SELECT symbol,SUM(shares) FROM orders WHERE user_id=? GROUP BY symbol", session["user_id"])
    stockList = []

    # Change list of dictionary to list of stock string
    for stock in portfolio:
        if stock["SUM(shares)"] > 0:    # if the total sum of shares is larger than 0 means the user own that stock
            stockList.append(stock["symbol"])

    if request.method == "POST":
        symbol = request.form.get("symbol")
        shares = request.form.get("shares")

        # Check if user selected a stock
        if not symbol:
            return apology("please select a stock to sell")

        # Check if user is trying to sell a stock user owns
        if symbol not in stockList:
            return apology("you do not own this stock")

        # Check if shares is not blank:
        if not shares:
            return apology("must enter share quantity")

        # Check if shares is a positive integer
        if not check_positive_integer(shares):
            return apology("shares has to be a valid positive integer")
        shares = int(shares)

        # Check how many shares of the symbol user owned. Take from list of dictionary the integer
        sharesOwned = (db.execute("SELECT SUM(shares) FROM orders WHERE user_id=? AND symbol=?", session["user_id"], symbol))[0]["SUM(shares)"]
        #print(sharesOwned)

        # Check is requested sell shares is less than or equal to sharesOwned
        if shares <= sharesOwned:
            # lookup current stock price
            stock = lookup(symbol)

            # log the sell into orders table
            db.execute("INSERT INTO orders (user_id, symbol, shares, price) VALUES (?, ?, ?, ?)", session["user_id"], stock["symbol"], shares*-1, stock["price"])

            # query current amount of cash. convert list of dictionary to just the cash value
            cash = (db.execute("SELECT cash FROM users WHERE id=?", session["user_id"]))[0]["cash"]

            cash += stock["price"] * shares

            # update cash in users
            db.execute("UPDATE users SET cash=? WHERE id=?", cash, session["user_id"])# Update user cash in db

            flash("Stock sold!")
            return redirect("/")

        return apology("too many shares")
    else:
        #print(portfolio)
        #print(stockList)
        return render_template("sell.html", portfolio = stockList)

@app.route("/changepassword", methods = ["POST", "GET"])
@login_required
def changePassword():
    if request.method == "POST":
        oldPassword = request.form.get("oldpassword")
        newPassword = request.form.get("newpassword")
        confirmation = request.form.get("confirmation")

        #Check if any of the field are empty
        if not oldPassword or not newPassword or not confirmation:
            return apology("password(s) cannot be blank")

        # Check that old password matches database
        db_oldPassword = (db.execute("SELECT hash FROM users WHERE id=?", session["user_id"]))[0]["hash"]
        if not check_password_hash(db_oldPassword, oldPassword):
            return apology("old password does not match")

        # Check if new password and confirmation match
        if newPassword != confirmation:
            return apology("new password confirmation does not match")

        # Check if old password and new password is different
        if newPassword == oldPassword:
            return apology("new password has to be different")

        # Update password in database
        newPasswordHash = generate_password_hash(newPassword)
        db.execute("UPDATE users SET hash=? WHERE id=?", newPasswordHash, session["user_id"])

        flash("Password updated!")
        return redirect("/")

    else:
        return render_template("changepassword.html")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)
