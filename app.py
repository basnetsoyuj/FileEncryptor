from flask import Flask, render_template, request, url_for, redirect, session, make_response
import pymongo
import bcrypt
import rsa
from io import BytesIO, StringIO
import random
from Crypto.Util import number

app = Flask(__name__)
app.secret_key = "test"
client = pymongo.MongoClient("localhost", 8848)

db = client.get_database('FileEncryptorDB')
records = db.users


class ShiftCipher:
    def __init__(self, shift_amt=None):
        self.shift_amt = shift_amt or 3

    @staticmethod
    def _change(text, amount):
        encrypted = ""
        for char in text:
            j = 97 if ord(char) > 96 else 65
            index = ord(char) - j
            if char.strip():
                encrypted += chr(j + ((index + amount) % 26))
            else:
                encrypted += char
        return encrypted

    def encrypt(self, text):
        return self._change(text, self.shift_amt)

    def decrypt(self, text):
        return self._change(text, -self.shift_amt)


class AffineCipher:
    def __init__(self, coeff=None, shift_amt=None):
        self.coeff = coeff or 7
        self.shift_amt = shift_amt or 5

    def encrypt(self, text):
        encrypted = ""
        for i in text:
            j = 97 if ord(i) > 96 else 65
            index = ord(i) - j
            encrypted += chr(j + ((self.coeff * index + self.shift_amt) % 26)) if i not in (" ", "\n") else i
        return encrypted

    def decrypt(self, text):
        decrypted = ""
        for i in text:
            j = 97 if ord(i) > 96 else 65
            index = ord(i) - j
            inverseA = pow(self.coeff, -1, 26)
            decrypted += chr(j + (inverseA * (index - self.shift_amt)) % 26) if i not in (" ", "\n") else i
        return decrypted


class BlockCipher:
    def __init__(self, block_size=None, dummy_char=None, map_=None):
        self.block_size = block_size or 5
        self.dummy_char = dummy_char or "X"
        if not map_:
            range_ = range(self.block_size)
            map_values = list(range_)
            random.shuffle(map_values)
            self.map_ = dict(zip(map_values, range_))
            self.inverse_map = dict(zip(range_, map_values))
        else:
            self.map_ = map_
            self.inverse_map = {v: k for k, v in self.map_.items()}

    def _change(self, text, lookup_dict):
        word_len = len(text) - text.count(" ") - text.count("\n") - text.count("\t")
        mod = word_len % self.block_size
        if mod:
            text += self.dummy_char * (self.block_size - mod)
        final_text = ""
        final_indices = []
        indices = []
        index = 0
        while index < len(text):
            if text[index].strip():
                indices.append(index)
            if len(indices) == self.block_size:
                final_indices.extend([indices[lookup_dict[i]] for i in range(self.block_size)])
                indices = []
            index += 1

        index = 0
        for char in text:
            if not char.strip():
                final_text += char
            else:
                final_text += text[final_indices[index]]
                index += 1
        return final_text

    def encrypt(self, text):
        return self._change(text, self.map_)

    def decrypt(self, text):
        return self._change(text, self.inverse_map).strip(self.dummy_char)


class RSA:
    def __init__(self, public_keypair=None, private_keypair=None):
        if public_keypair and private_keypair:
            self.public_keypair, self.private_keypair = public_keypair, private_keypair
        else:
            self.n_bytes = 30
            self.prime1 = number.getPrime(self.n_bytes)
            self.prime2 = number.getPrime(self.n_bytes)
            while self.prime1 == self.prime2:
                self.prime2 = number.getPrime(self.n_bytes)
            # self.prime1, self.prime2 = 983, 37
            self.public_keypair, self.private_keypair = self.generate_keypair(self.prime1, self.prime2)

    @staticmethod
    def gcd(a, b):
        while b != 0:
            a, b = b, a % b
        return a

    @staticmethod
    def is_prime(num):
        if num == 2:
            return True
        if num < 2 or num % 2 == 0:
            return False
        for n in range(3, int(num ** 0.5) + 2, 2):
            if num % n == 0:
                return False
        return True

    @staticmethod
    def generate_keypair(p, q):
        n = p * q
        phi = (p - 1) * (q - 1)
        e = random.randrange(1, phi)

        g = RSA.gcd(e, phi)
        while g != 1:
            e = random.randrange(1, phi)
            g = RSA.gcd(e, phi)

        d = pow(e, -1, phi)

        return (e, n), (d, n)

    def encrypt(self, plaintext):
        key, n = self.public_keypair
        cipher = [str(pow(ord(char), key, n)) for char in plaintext]
        return " ".join(cipher)

    def decrypt(self, ciphertext):
        ciphertext = ciphertext.split(" ")
        key, n = self.private_keypair
        plain = [chr(pow(int(char), key, n)) for char in ciphertext]
        return ''.join(plain)


@app.route("/register", methods=['post', 'get'])
def register():
    message = ''
    if "email" in session:
        return redirect(url_for("index"))
    if request.method == "POST":
        user = request.form.get("username")
        email = request.form.get("email")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")
        user_found = records.find_one({"name": user})
        email_found = records.find_one({"email": email})
        if user_found:
            message = 'Username already exists!'
            return render_template('register.html', message=message)
        if email_found:
            message = 'Email already exists!'
            return render_template('register.html', message=message)
        if password1 != password2:
            message = 'Passwords do not match!'
            return render_template('register.html', message=message)
        else:
            hashed = bcrypt.hashpw(password2.encode('utf-8'), bcrypt.gensalt())
            pubkey, private_key = rsa.newkeys(512)
            rsa_obj = RSA()
            user_input = {'name': user, 'email': email, 'password': hashed, 'public_key': pubkey.save_pkcs1(),
                          'private_key': private_key.save_pkcs1(), 'custom_public_key': str(rsa_obj.public_keypair),
                          'custom_private_key': str(rsa_obj.private_keypair)}
            records.insert_one(user_input)
            session["email"] = email
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
        email_found = records.find_one({"email": email})
        if email_found:
            email_val = email_found['email']
            passwordcheck = email_found['password']
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


def search(email):
    return search(email)


@app.route("/rsa/convert", methods=['post', 'get'])
def convert():
    email = session.get('email')
    pubkey = ""
    private_key = ""
    if email:
        user = search(email)
        if user:
            pubkey = rsa.PublicKey.load_pkcs1(user.get('public_key'))
            private_key = rsa.PrivateKey.load_pkcs1(user.get('private_key'))
        value_dict = {'email': email, 'pubkey': pubkey.save_pkcs1().decode(),
                      'private_key': private_key.save_pkcs1().decode()}
        if request.method == "POST":
            if request.form.get("toggle") == "encrypt":
                value_dict['raw_text'] = request.form.get("raw_text")
                value_dict['encrypted_message'] = rsa.encrypt(value_dict['raw_text'].encode('utf8'), pub_key=pubkey)
            else:
                value_dict['encrypted_message'] = request.form.get("encrypted_message")
                value_dict['raw_text'] = rsa.decrypt(eval(value_dict['encrypted_message'].encode('utf-8')),
                                                     private_key).decode()
        return render_template('rsa_convert.html', **value_dict)
    return render_template('rsa_convert.html', email=None)


@app.route("/rsa/convert_file", methods=['post', 'get'])
def convert_file():
    email = session.get('email')
    pubkey = ""
    private_key = ""
    if email:
        user = search(email)
        if user:
            pubkey = rsa.PublicKey.load_pkcs1(user.get('public_key'))
            private_key = rsa.PrivateKey.load_pkcs1(user.get('private_key'))
        value_dict = {'email': email, 'pubkey': pubkey.save_pkcs1().decode(),
                      'private_key': private_key.save_pkcs1().decode()}
        if request.method == "POST":
            f = request.files['file']
            if request.form.get("toggle") == "encrypt":
                encrypted_message = rsa.encrypt(f.read(), pub_key=pubkey)
                bi = BytesIO()
                bi.write(encrypted_message)
                output = make_response(bi.getvalue())
                output.headers["Content-Disposition"] = f"attachment; filename={f.filename}.encrypted"
                output.headers["Content-type"] = "text/plain"
                return output
            else:
                decrypted_message = rsa.decrypt(f.read(), priv_key=private_key).decode()
                bi = StringIO()
                bi.write(decrypted_message)
                output = make_response(bi.getvalue())
                output.headers["Content-Disposition"] = f"attachment; filename={f.filename.replace('.encrypted', '')}"
                output.headers["Content-type"] = "text/plain"
                return output
        return render_template('rsa_convert_file.html', **value_dict)
    return render_template('rsa_convert_file.html', email=None)


@app.route("/custom-rsa/convert", methods=['post', 'get'])
def custom_convert():
    email = session.get('email')
    pubkey = ""
    private_key = ""
    if email:
        user = search(email)
        if user:
            pubkey = eval(user.get('custom_public_key'))
            private_key = eval(user.get('custom_private_key'))
        value_dict = {'email': email, 'pubkey': str(pubkey),
                      'private_key': str(private_key)}
        if request.method == "POST":
            rsa_obj = RSA(pubkey, private_key)
            if request.form.get("toggle") == "encrypt":
                value_dict['raw_text'] = request.form.get("raw_text")
                value_dict['encrypted_message'] = rsa_obj.encrypt(value_dict['raw_text'])
            else:
                value_dict['encrypted_message'] = request.form.get("encrypted_message")
                value_dict['raw_text'] = rsa_obj.decrypt(value_dict['encrypted_message'])
        return render_template('custom_rsa_convert.html', **value_dict)
    return render_template('custom_rsa_convert.html', email=None)


@app.route("/custom-rsa/convert_file", methods=['post', 'get'])
def custom_rsa_convert_file():
    email = session.get('email')
    pubkey = ""
    private_key = ""
    if email:
        user = search(email)
        if user:
            pubkey = eval(user.get('custom_public_key'))
            private_key = eval(user.get('custom_private_key'))
        value_dict = {'email': email, 'pubkey': str(pubkey),
                      'private_key': str(private_key)}
        if request.method == "POST":
            rsa_obj = RSA(pubkey, private_key)
            f = request.files['file']
            if request.form.get("toggle") == "encrypt":
                encrypted_message = rsa_obj.encrypt(f.read().decode())
                bi = StringIO()
                bi.write(encrypted_message)
                output = make_response(bi.getvalue())
                output.headers["Content-Disposition"] = f"attachment; filename={f.filename}.encrypted"
                output.headers["Content-type"] = "text/plain"
                return output
            else:
                decrypted_message = rsa_obj.decrypt(f.read().decode())
                bi = StringIO()
                bi.write(decrypted_message)
                output = make_response(bi.getvalue())
                output.headers["Content-Disposition"] = f"attachment; filename={f.filename.replace('.encrypted', '')}"
                output.headers["Content-type"] = "text/plain"
                return output
        return render_template('custom_rsa_convert_file.html', **value_dict)
    return render_template('custom_rsa_convert_file.html', email=None)


@app.route("/", methods=['post', 'get'])
def index():
    email = session.get('email')
    return render_template('index.html', email=email)


@app.route("/other-ciphers", methods=['post', 'get'])
def other_ciphers():
    email = session.get('email')
    if email:
        value_dict = {'email': email, **dict(request.form)}
        if request.method == "POST":
            if request.form.get('cipher_type') == "shift":
                encryptor = ShiftCipher(int(request.form.get('s_shift_amount')))
            elif request.form.get("cipher_type") == "affine":
                encryptor = AffineCipher(int(request.form.get('a_coeff')), int(request.form.get('a_shift_amount')))
            elif request.form.get("cipher_type") == "block":
                map_ = request.form.get('b_map')
                if map_:
                    map_ = eval(map_)
                encryptor = BlockCipher(block_size=int(request.form.get('b_block_size')), map_=map_)
            else:
                value_dict['message'] = "Please choose a cipher type."
                return render_template('other_ciphers.html', **value_dict)
            if request.form.get("toggle") == "encrypt":
                value_dict['raw_text'] = request.form.get("raw_text")
                value_dict['encrypted_message'] = encryptor.encrypt(value_dict['raw_text'])
            else:
                value_dict['encrypted_message'] = request.form.get("encrypted_message")
                value_dict['raw_text'] = encryptor.decrypt(value_dict['encrypted_message'])
        return render_template('other_ciphers.html', **value_dict)
    return render_template('other_ciphers.html', email=None)


if __name__ == "__main__":
    app.run(debug=True)
