from flask import Flask, request, render_template
import requests
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from crypto.rsa.rsatest import request_key, rsa_dec
from AES.aes import aes_cbc_encrypt, aes_cbc_decrypt
import base64
app = Flask(__name__, template_folder="../templates", static_folder="../static")

FATMA_NODE_URL = "http://127.0.0.1:5862/receive"
KARIM_NODE_URL = "http://127.0.0.1:5863/receive"
inbox_messages = []
Y_pub_key, Y_prv_key = request_key()
F_key, K_key = None, None
sent_my_key_to_F, sent_my_key_to_K = False, False
shared_key, initial_vector = None, None

@app.route("/", methods=["GET", "POST"])
def home():
    global sent_my_key_to_F, sent_my_key_to_K
    global shared_key

    status = ""


    if request.method == "POST":
        msg = request.form.get("msg")

        if F_key is None and K_key is None: status = "Can't comunicate with Fatma neither Karim right now. "
        else:
            if F_key is None:
                status = "Can't comunicate with Fatma right now She's offline"
            else:
                if shared_key is None or initial_vector is None:
                    status = "I don't have the shared Key"
                else:
                    enc_msg = aes_cbc_encrypt(msg.encode(), shared_key, initial_vector)
                    #enc_msg = rsa_enc(msg, F_key)
                    #print(f"enc_msg: {enc_msg}")
                    payload = {
                        "type":"message",
                        "enc_msg": base64.b64encode(enc_msg).decode(), 
                        "sender":"Youssef"
                    }

                    try:
                        requests.post(
                            FATMA_NODE_URL,
                            json=payload,
                            headers={"Content-Type": "application/json"},
                            timeout=1
                        )
                        status = "Message sent!"
                    except:
                        status = "Fatma didn't receive the message"
                
            if K_key is None:
                status = "Can't comunicate with Karim right now, He's offline"
            else:
                if shared_key is None or initial_vector is None:
                    status = "I don't have the shared Key"
                else:
                    enc_msg = aes_cbc_encrypt(msg.encode(), shared_key, initial_vector)                    
                    #enc_msg = rsa_enc(msg, K_key)
                    #print(f"enc_msg: {enc_msg}")
                    payload = {
                        "type":"message",
                        "enc_msg": base64.b64encode(enc_msg).decode(), 
                        "sender":"Youssef"
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

        inbox_messages.append(f"Youssef: {msg}")




    if request.method == "GET":
        if sent_my_key_to_F is False:
        
            payload = {
                "type":"Y_key", 
                "Author":"Youssef", 
                "n": Y_pub_key[0], 
                "e": Y_pub_key[1]
            }
            try:
                requests.post(
                    FATMA_NODE_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=1
                )
                sent_my_key_to_F = True
            except:
                status = "Fatma didn't receive the Key"
        if sent_my_key_to_K is False:
            
            payload = {
                "type":"Y_key", 
                "Author":"Youssef", 
                "n": Y_pub_key[0], 
                "e": Y_pub_key[1]
            }
            try:
                requests.post(
                    KARIM_NODE_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=1
                )
                status = "Key sent!"
                sent_my_key_to_K = True
            except:
                if sent_my_key_to_F is False:
                    status =  "Fatma & Karim didn't receive the Key"
                else:
                    status =  "Karim didn't receive the Key"

        print(f"Fatma key: {F_key} \n Karim key: {K_key}")

    return render_template("chat.html", inbox=inbox_messages, status=status, sender="Youssef", receiver="💎Diamonds")

# RECEIVING (JSON POST)
@app.route("/receive", methods=["POST"])
def receive():
    global F_key, K_key
    global shared_key, initial_vector

    data = request.get_json() # dict
    if data["type"] == "F_key":
        F_key = (data["n"],data["e"])
    elif data["type"] == "K_key":
        K_key = (data["n"],data["e"])
    elif data["type"] == "AES-key":
        print("Youssef trying to receive aes key")
        shared_key = (rsa_dec(data["key"], Y_prv_key))
        initial_vector = base64.b64decode(data["IV"])

        print(f"Youssef received shared key: {shared_key}")
        print(f"Youssef received initial: {initial_vector}")
    else:
        ciphertext = base64.b64decode(data["enc_msg"])
        dec_msg = aes_cbc_decrypt(
            ciphertext, 
            shared_key, 
            initial_vector)
        #dec_msg = rsa_dec(int(data["msg"]), Y_prv_key)
        inbox_messages.append(f"{data["sender"]}: {dec_msg.decode()}")
    return {"status": "received"}


@app.route("/inbox_api")
def inbox_api():
    return {"messages": inbox_messages}


if __name__ == "__main__":
    app.run(port=5873, debug=True)
