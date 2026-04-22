from flask import Flask, render_template, request
from crypto.classical.Ceasar_Cipher import ceasar_bf
from Hashing.SHA256 import generate_hash
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


# SHA-256 hashing route
@app.route('/sha256', methods=['GET', 'POST'])
def sha256():
    output = ""
    text = ""

    if request.method == "POST":
        text = request.form.get("text")

        # If text is provided, compute its SHA-256 hash
        if text:
            sha256_hash = generate_hash(text)
            output = sha256_hash    
    return render_template("SHA256.html", output=output, text=text)



if __name__ == "__main__":
    app.run(port=5000, debug=True)
