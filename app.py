
from Hashing.bcrypt_hash import hash_password, verify_password
from flask import Flask, render_template, request
from crypto.classical.Ceasar_Cipher import ceasar_bf
from Hashing.SHA256 import generate_hash
from Hashing.SHA1 import generate_sha1
import os
from multiprocessing import Pool, cpu_count

app = Flask(__name__)

@app.route('/')
def home():
    return render_template("index.html")

@app.route('/ceaser', methods=['GET', 'POST'])
def ceaser():
    output = ""
    text = ""
    key = ""

    if request.method == "POST":
        text = request.form.get("text")
        key = request.form.get("key")
        mode = request.form.get("mode")

        if mode == "encrypt":
            output = ceasar_bf(text, int(key))
        else:
            output = ceasar_bf(text, -int(key))

    return render_template("ceaser.html", output=output, text=text, key=key)



# SHA-256 hashing function for files

@app.route('/sha256', methods=['GET', 'POST'])
def sha256():
    output = ""
    text = ""
    file_hash = "" 

    if request.method == "POST":
        text = request.form.get("text")

        # If text is provided, compute its SHA-256 hash
        if text:
            output = generate_hash(text)  # Use your custom generate_hash for text

        # If a file is provided, compute its SHA-256 hash
        file = request.files.get("file")
        if file:
            file_hash = generate_hash(file.read())  # Hash the uploaded file using your custom implementation

    return render_template("SHA256.html", output=output, text=text, file_hash=file_hash)


@app.route('/sha1', methods=['GET', 'POST'])
def sha1():
    output = ""
    text = ""

    if request.method == "POST":
        text = request.form.get("text")

        if text:
            output = generate_sha1(text)

    return render_template("SHA1.html", output=output, text=text)



@app.route('/bcrypt', methods=['GET', 'POST'])
def bcrypt_page():
    hash_output = ""
    text = ""
    error = ""
    verify_result = None
    verify_password_input = ""
    verify_hash_input = ""

    if request.method == "POST":
        text = request.form.get("text", "")
        if text:
            try:
                hash_output = hash_password(text, rounds=12)
            except ValueError as exc:
                error = str(exc)
        else:
            error = "Please enter a password to hash."

    return render_template(
        "bcrypt.html",
        hash_output=hash_output,
        text=text,
        verify_result=verify_result,
        verify_password_input=verify_password_input,
        verify_hash_input=verify_hash_input,
        error=error,
    )


@app.route('/bcrypt/verify', methods=['POST'])
def bcrypt_verify():
    password_input = request.form.get("password", "")
    hash_input = request.form.get("hashed", "")
    result = None
    error = ""

    if password_input and hash_input:
        result = verify_password(password_input, hash_input)
    else:
        error = "Both fields are required for verification."

    return render_template(
        "bcrypt.html",
        hash_output=hash_input,
        text="",
        verify_result=result,
        verify_password_input=password_input,
        verify_hash_input=hash_input,
        error=error,
    )

if __name__ == "__main__":
    app.run(port=5000, debug=True)



