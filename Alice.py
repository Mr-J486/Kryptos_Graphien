from flask import Flask, request, render_template
import requests
from crypto.rsa.rsatest import request_key, rsa_test, rsa_enc, rsa_dec

app = Flask(__name__)

NODE_B_URL = "http://127.0.0.1:5002/receive"
inbox_messages = []
A_pub_key, A_prv_key = request_key()
B_key = None
sent_my_key = False
@app.route("/", methods=["GET", "POST"])
def home():
    global sent_my_key
    status = ""


    if request.method == "POST":
        if B_key is None:
            status = "Can't comunicate with Bob right now He's offline"
        else:
            msg = request.form.get("msg")
            enc_msg = rsa_enc(msg, B_key)
            #print(f"enc_msg: {enc_msg}")
            payload = {"type":"message","msg": str(enc_msg)}


            try:
                requests.post(
                    NODE_B_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                status = "Message sent!"
                inbox_messages.append(f"Alice: {msg}")
            except:
                status = "Bob didn't receive the message"


    if request.method == "GET" and sent_my_key is False:
        
        payload = {"type":"key", "n": A_pub_key[0], "e": A_pub_key[1]}
        try:
                requests.post(
                    NODE_B_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                status = "Key sent!"
                sent_my_key = True
        except:
            status = "Bob didn't receive the Key"

        print(f"Bob key: {B_key}")

    return render_template("chat.html", inbox=inbox_messages, status=status, sender="Alice", receiver="Bob")


@app.route("/receive", methods=["POST"])
def receive():
    global B_key
    data = request.get_json() # dict
    if data["type"] == "key":
        B_key = (data["n"], data["e"])
    else:
        dec_msg = rsa_dec(int(data["msg"]), A_prv_key)
        inbox_messages.append(f"Bob: {dec_msg}")
    return {"status": "received"}


@app.route("/inbox_api")
def inbox_api():
    return {"messages": inbox_messages}


if __name__ == "__main__":
    app.run(port=5001, debug=True)
