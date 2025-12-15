from flask import Flask, request, render_template
import requests
from crypto.rsa.rsatest import request_key, rsa_dec
from AES.aes import aes_cbc_encrypt, aes_cbc_decrypt
import base64
app = Flask(__name__)

NODE_B_URL = "http://127.0.0.1:5001/receive"
inbox_messages = []
B_pub_key, B_prv_key = request_key()
A_key = None
sent_my_key = False
shared_key = None
initial_vector = None
@app.route("/", methods=["GET", "POST"])
def home():
    global sent_my_key, shared_key
    status = ""

    if request.method == "POST":
        if A_key is None:
            status = "Can't comunicate with Alice right now He's offline"
        else:
            if shared_key is None or initial_vector is None:
                status = "I don't have the shared Key"

            else:
                msg = request.form.get("msg")
                #enc_msg = rsa_enc(msg, A_key)
                enc_msg = aes_cbc_encrypt(msg.encode(), shared_key, initial_vector)

                #print(f"enc_msg: {enc_msg}")
                payload = {
                    "type":"message", 
                    "enc_msg": base64.b64encode(enc_msg).decode()}

                try:
                    requests.post(
                        NODE_B_URL,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=5
                    )
                    status = "Message sent!"
                    inbox_messages.append(f"Bob: {msg}")

                except:
                    status = "Alice didn't receive the message"

    if request.method == "GET" and sent_my_key is False:
        payload = {"type":"B_key", "n": B_pub_key[0], "e": B_pub_key[1]}
        try:
            requests.post(
                NODE_B_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            status = "Bob key sent!"
            sent_my_key = True
        except:
            status = "Alice didn't receive the Key"

    print(f"Alice key: {A_key}")

    return render_template("chat.html", inbox=inbox_messages, status=status, sender="Bob", receiver="Alice")

@app.route("/receive", methods=["POST"])
def receive():
    global A_key,shared_key, initial_vector
    data = request.get_json() # dict
    if data["type"] == "A_key":
        A_key = (data["n"],data["e"])
    elif data["type"] == "AES-key":
        print("bob trying to receive aes key")
        shared_key = (rsa_dec(data["key"], B_prv_key))
        initial_vector = base64.b64decode(data["IV"])

        print(f"bob received shared key: {shared_key}")
        print(f"bob received initial: {initial_vector}")
    else:
        #dec_msg = rsa_dec(int(data["msg"]), B_prv_key)
        ciphertext = base64.b64decode(data["enc_msg"])
        dec_msg = aes_cbc_decrypt(
            ciphertext, 
            shared_key, 
            initial_vector)
        inbox_messages.append(f"Alice: {dec_msg.decode()}")
    return {"status": "received"}

@app.route("/inbox_api")
def inbox_api():
    return {"messages": inbox_messages}

if __name__ == "__main__":
    app.run(port=5002, debug=True)
