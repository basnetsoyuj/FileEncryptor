from flask import Flask, render_template, request, url_for, redirect, session
import pymongo
import bcrypt
import rsa

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
            pubkey, private_key = rsa.newkeys(512)
            user_input = {'name': user, 'email': email, 'password': hashed, 'public_key': pubkey.save_pkcs1(),
                          'private_key': private_key.save_pkcs1()}
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
    email = session.get('email')
    pubkey = ""
    private_key = ""
    if email:
        user = records.find_one({'email': email})
        if user:
            pubkey = rsa.PublicKey.load_pkcs1(user.get('public_key'))
            private_key = rsa.PrivateKey.load_pkcs1(user.get('private_key'))
        value_dict = {'email': email, 'pubkey': pubkey.save_pkcs1().decode(), 'private_key': private_key.save_pkcs1().decode()}
        if request.method == "POST":
            # if request.form.get("toggle") == "encrypt":
            print(request.form.get('toggle'))
            value_dict['raw_text'] = request.form.get("raw_text")
            value_dict['encrypted_message'] = str(rsa.encrypt(value_dict['raw_text'].encode('utf8'), pub_key=pubkey))
            # else:
            #     value_dict['encrypted_message'] = request.form.get("encrypted_message")
            #     value_dict['raw_text'] = rsa.decrypt(value_dict['encrypted_message'], private_key)
        return render_template('index.html', **value_dict)
    return render_template('index.html', email=None)


if __name__ == "__main__":
    app.run(debug=True)
