from flask import Flask, render_template, request
from crypto.classical.Ceasar_Cipher import ceasar_bf
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

if __name__ == "__main__":
    app.run(port=5000, debug=True)
