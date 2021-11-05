from flask import Flask, render_template, request, url_for, redirect, session
import pymongo
import bcrypt

# set app as a Flask instance
app = Flask(__name__)
# encryption relies on secret keys so they could be run
app.secret_key = "testing"
# connect to your Mongo DB database
client = pymongo.MongoClient("localhost", 8848)

# get the database name
db = client.get_database('FileEncryptorDB')
# get the particular collection that contains the data
records = db.users


# assign URLs to have a particular route
@app.route("/register", methods=['post', 'get'])
def register():
    message = ''
    # if method post in index
    if "email" in session:
        return redirect(url_for("index"))
    if request.method == "POST":
        user = request.form.get("fullname")
        email = request.form.get("email")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        # if found in database showcase that it's found
        user_found = records.find_one({"name": user})
        email_found = records.find_one({"email": email})
        if user_found:
            message = 'There already is a user by that name'
            return render_template('register.html', message=message)
        if email_found:
            message = 'This email already exists in database'
            return render_template('register.html', message=message)
        if password1 != password2:
            message = 'Passwords should match!'
            return render_template('register.html', message=message)
        else:
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            user_input = {'name': user, 'email': email, 'password': hashed}
            records.insert_one(user_input)
            return redirect(url_for("index"))
    return render_template('register.html')


@app.route("/login", methods=["POST", "GET"])
def login():
    message = 'Please login to your account'
    if "email" in session:
        return redirect(url_for("index"))

    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        # check if email exists in database
        email_found = records.find_one({"email": email})
        if email_found:
            email_val = email_found['email']
            passwordcheck = email_found['password']
            # encode the password and check if it matches
            if bcrypt.checkpw(password.encode('utf-8'), passwordcheck):
                session["email"] = email_val
                return redirect(url_for('index'))
            else:
                if "email" in session:
                    return redirect(url_for("index"))
                message = 'Wrong password'
                return render_template('login.html', message=message)
        else:
            message = 'Email not found'
            return render_template('login.html', message=message)
    return render_template('login.html', message=message)


@app.route("/logout", methods=["POST", "GET"])
def logout():
    if "email" in session:
        session.pop("email", None)
    return redirect(url_for('index'))


@app.route("/", methods=['post', 'get'])
def index():
    return render_template('index.html', email=session.get("email"))


if __name__ == "__main__":
    app.run(debug=True)
