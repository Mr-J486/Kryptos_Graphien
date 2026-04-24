# from flask import Flask, request, render_template
# import requests
# from crypto.rsa.rsatest import request_key, rsa_enc
# from AES.aes import aes_cbc_encrypt, aes_cbc_decrypt
# import base64
# app = Flask(__name__)

# NODE_B_URL = "http://127.0.0.1:5002/receive"
# inbox_messages = []
# A_pub_key, A_prv_key = request_key()
# B_key = None
# sent_my_key = False
# shared_key = b"ThisIsA16ByteKey"
# initial_vector = b"RandomInitVector"
# sent_AES_key = False
# @app.route("/", methods=["GET", "POST"])
# def home():
#     global sent_my_key, B_key, sent_AES_key,shared_key, initial_vector
#     status = ""


#     if request.method == "POST":
#         if B_key is None:
#             status = "Can't comunicate with Bob right now He's offline"
#         else:
#             msg = request.form.get("msg")
#             #enc_msg = rsa_enc(msg, B_key)
#             print(f"initial vector tyb is")
#             enc_msg = aes_cbc_encrypt(msg.encode(), shared_key, initial_vector)
            
#             print(f"encrypting 'hello': {enc_msg}")
            
#             payload = {
#                 "type":"message",
#                 "enc_msg": base64.b64encode(enc_msg).decode()}


#             try:
#                 requests.post(
#                     NODE_B_URL,
#                     json=payload,
#                     headers={"Content-Type": "application/json"},
#                     timeout=5
#                 )
#                 status = "Message sent!"
#                 inbox_messages.append(f"Alice: {msg}")
#             except:
#                 status = "Bob didn't receive the message"

#     # send my public key
#     if request.method == "GET" and sent_my_key is False:
        
#         payload = {"type":"A_key", "n": A_pub_key[0], "e": A_pub_key[1]}
#         try:
#             requests.post(
#                 NODE_B_URL,
#                 json=payload,
#                 headers={"Content-Type": "application/json"},
#                 timeout=5
#             )
#             status = "Alice key sent!"
#             sent_my_key = True
#         except:
#             status = "Bob didn't receive the Key"

#     print(f"Bob key: {B_key}")
    
#     if request.method == "GET" and B_key is not None and sent_AES_key is False:
#         print(f"shared key decoded test at alice: {shared_key.decode()}")
#         enc_shared_key = rsa_enc(shared_key, B_key)
#         print(f"shared_key: {shared_key}")

#         payload = {
#             "type":"AES-key",
#             "key": enc_shared_key, 
#             "IV": base64.b64encode(initial_vector).decode()}

#         try:
#             requests.post(
#                 NODE_B_URL,
#                 json=payload,
#                 headers={"Content-Type": "application/json"},
#                 timeout=5
#             )
#             status = "AES-Key sent"
#             sent_AES_key = True
#             print(f"shared_key sent to bob: {shared_key}")

#         except:
#             status = "Bob didn't receive the shared key"


#     return render_template("chat.html", inbox=inbox_messages, status=status, sender="Alice", receiver="Bob")


# @app.route("/receive", methods=["POST"])
# def receive():
#     global B_key, shared_key, initial_vector
#     data = request.get_json() # dict
#     if data["type"] == "B_key":
#         B_key = (data["n"], data["e"])
#     elif data["type"] == "message":
#         #dec_msg = rsa_dec(int(data["msg"]), A_prv_key)
#         print(type(data["enc_msg"]))
#         ciphertext = base64.b64decode(data["enc_msg"])
#         dec_msg = aes_cbc_decrypt(
#             ciphertext, 
#             shared_key, 
#             initial_vector)
#         inbox_messages.append(f"Bob: {dec_msg.decode()}")
#     return {"status": "received"}


# @app.route("/inbox_api")
# def inbox_api():
#     return {"messages": inbox_messages}


# if __name__ == "__main__":
#     app.run(port=5001, debug=True)

from flask import Flask, request, render_template
import requests
from crypto.rsa.rsatest import request_key, rsa_enc
from AES.aes import aes_cbc_encrypt, aes_cbc_decrypt
from Hashing.MD5 import hmac_md5
import base64

app = Flask(__name__)

NODE_B_URL = "http://127.0.0.1:5002/receive"
inbox_messages = []
A_pub_key, A_prv_key = request_key()
B_key = None
sent_my_key = False
shared_key = b"ThisIsA16ByteKey"
initial_vector = b"RandomInitVector"
sent_AES_key = False


@app.route("/", methods=["GET", "POST"])
def home():
    global sent_my_key, B_key, sent_AES_key, shared_key, initial_vector
    status = ""

    if request.method == "POST":
        if B_key is None:
            status = "Can't comunicate with Bob right now He's offline"
        else:
            msg = request.form.get("msg")
            enc_msg = aes_cbc_encrypt(msg.encode(), shared_key, initial_vector)
            msg_hmac = hmac_md5(shared_key, msg)

            payload = {
                "type": "message",
                "enc_msg": base64.b64encode(enc_msg).decode(),
                "md5": msg_hmac
            }

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
        payload = {"type": "A_key", "n": A_pub_key[0], "e": A_pub_key[1]}
        try:
            requests.post(
                NODE_B_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            status = "Alice key sent!"
            sent_my_key = True
        except:
            status = "Bob didn't receive the Key"

    print(f"Bob key: {B_key}")

    if request.method == "GET" and B_key is not None and sent_AES_key is False:
        enc_shared_key = rsa_enc(shared_key, B_key)

        payload = {
            "type": "AES-key",
            "key": enc_shared_key,
            "IV": base64.b64encode(initial_vector).decode()
        }

        try:
            requests.post(
                NODE_B_URL,
                json=payload,
                headers={"Content-Type": "application/json"},
                timeout=5
            )
            status = "AES-Key sent"
            sent_AES_key = True

        except:
            status = "Bob didn't receive the shared key"

    return render_template("chat.html", inbox=inbox_messages, status=status, sender="Alice", receiver="Bob")


@app.route("/receive", methods=["POST"])
def receive():
    global B_key, shared_key, initial_vector
    data = request.get_json()

    if data["type"] == "B_key":
        B_key = (data["n"], data["e"])

    elif data["type"] == "message":
        ciphertext = base64.b64decode(data["enc_msg"])
        dec_msg = aes_cbc_decrypt(ciphertext, shared_key, initial_vector)

        plain_text = dec_msg.decode()
        received_hmac = data.get("md5", "")
        calculated_hmac = hmac_md5(shared_key, plain_text)

        if received_hmac == calculated_hmac:
            inbox_messages.append(f"Bob: {plain_text} [OK]")
        else:
            inbox_messages.append(f"Bob: {plain_text} [TAMPERED]")

    return {"status": "received"}


@app.route("/inbox_api")
def inbox_api():
    return {"messages": inbox_messages}


if __name__ == "__main__":
    app.run(port=5001, debug=True)