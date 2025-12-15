from flask import Flask, request, render_template
import requests
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from crypto.rsa.rsatest import request_key, rsa_enc
from AES.aes import aes_cbc_encrypt, aes_cbc_decrypt
import base64

app = Flask(__name__, template_folder="../templates", static_folder="../static")

KARIM_NODE_URL = "http://127.0.0.1:5863/receive"
YOUSSEF_NODE_URL = "http://127.0.0.1:5873/receive"
inbox_messages = []
F_pub_key, F_prv_key = request_key()
K_key, Y_key = None, None
sent_my_key_to_K, sent_my_key_to_Y = False, False
shared_key = b"ThisIsA16ByteKey"
initial_vector = b"RandomInitVector"
sent_AES_to_K, sent_AES_to_Y = False, False
@app.route("/", methods=["GET", "POST"])
def home():
    global sent_my_key_to_K, sent_my_key_to_Y
    global K_key, Y_key
    global sent_AES_to_K, sent_AES_to_Y
    global shared_key, initial_vector
    status = ""


    if request.method == "POST":
        msg = request.form.get("msg")
        
        if K_key is None and Y_key is None: status = "Can't comunicate with Karim neither Youssef right now. "
        else:
            if K_key is None:
                status = "Can't comunicate with Karim right now He's offline"
            else:
                #enc_msg = rsa_enc(msg, K_key)
                enc_msg = aes_cbc_encrypt(msg.encode(), shared_key, initial_vector)

                #print(f"enc_msg: {enc_msg}")
                payload = {
                    "type":"message",
                    "enc_msg": base64.b64encode(enc_msg).decode(), 
                    "sender":"Fatma"
                }


                try:
                    requests.post(
                        KARIM_NODE_URL,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=1
                    )
                    status = "Message sent!"
                except:
                    status = "Karim didn't receive the message"
            
            if Y_key is None:
                status = "Can't comunicate with Youssef right now He's offline"
            else:
                #enc_msg = rsa_enc(msg, Y_key)
                enc_msg = aes_cbc_encrypt(msg.encode(), shared_key, initial_vector)

                #print(f"enc_msg: {enc_msg}")
                payload = {
                    "type":"message",
                    "enc_msg": base64.b64encode(enc_msg).decode(), 
                    "sender":"Fatma"
                }


                try:
                    requests.post(
                        YOUSSEF_NODE_URL,
                        json=payload,
                        headers={"Content-Type": "application/json"},
                        timeout=1
                    )
                    status = "Message sent!"
                except:
                    status = "Youssef didn't receive the message"
            
        inbox_messages.append(f"Fatma: {msg}")




    if request.method == "GET":
        if sent_my_key_to_K is False:
        
            payload = {
                "type":"F_key", 
                "Author":"Fatma", 
                "n": F_pub_key[0], 
                "e": F_pub_key[1]
            }
            try:
                requests.post(
                    KARIM_NODE_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=1
                )
                sent_my_key_to_K = True
            except:
                status = "Karim didn't receive the Key"
        if sent_my_key_to_Y is False:
            payload = {
                "type":"F_key", 
                "Author":"Fatma", 
                "n": F_pub_key[0], 
                "e": F_pub_key[1]
            }
            try:
                requests.post(
                    YOUSSEF_NODE_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=1
                )
                if sent_my_key_to_K == False:
                    status = "Karim didn't receive the Key"
                else:
                    status = "Key sent!"
                sent_my_key_to_Y = True
            except:
                if sent_my_key_to_K is False:
                    status =  "Karim & Youssef didn't receive the Key"
                else:
                    status =  "Youssef didn't receive the Key"

        print(f"Karim key: {K_key} \n Youssef key: {Y_key}")

        if K_key is not None and sent_AES_to_K is False:
            enc_shared_key = rsa_enc(shared_key, K_key)

            payload = {
            "type":"AES-key",
            "key": enc_shared_key, 
            "IV": base64.b64encode(initial_vector).decode()}

            try:
                requests.post(
                    KARIM_NODE_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                status = "AES-Key sent to Karim"
                sent_AES_to_K = True
                print(f"shared_key sent to Karim: {shared_key}")

            except:
                status = "Karim didn't receive the AES key"
    
        if Y_key is not None and sent_AES_to_Y is False:
            enc_shared_key = rsa_enc(shared_key, Y_key)

            payload = {
            "type":"AES-key",
            "key": enc_shared_key, 
            "IV": base64.b64encode(initial_vector).decode()}

            try:
                requests.post(
                    YOUSSEF_NODE_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=5
                )
                status = "AES-Key sent to Youssef"
                sent_AES_to_Y = True
                print(f"shared_key sent to Youssef: {shared_key}")

            except:
                status = "Youssef didn't receive the AES key"





    return render_template("chat.html", inbox=inbox_messages, status=status, sender="Fatma", receiver="💎Diamonds")

# RECEIVING (JSON POST)
@app.route("/receive", methods=["POST"])
def receive():
    global K_key, Y_key
    global shared_key, initial_vector
    data = request.get_json() # dict
    if data["type"] == "K_key":
            K_key = (data["n"],data["e"])
    elif data["type"] == "Y_key":
            Y_key = (data["n"],data["e"])
    else:
        ciphertext = base64.b64decode(data["enc_msg"])
        dec_msg = aes_cbc_decrypt(
            ciphertext, 
            shared_key, 
            initial_vector)
        inbox_messages.append(f"{data["sender"]}: {dec_msg.decode()}")
    return {"status": "received"}


@app.route("/inbox_api")
def inbox_api():
    return {"messages": inbox_messages}


if __name__ == "__main__":
    app.run(port=5862, debug=True)
