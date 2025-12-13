from flask import Flask, request, render_template
import requests
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from crypto.rsa.rsatest import request_key, rsa_test, rsa_enc, rsa_dec
app = Flask(__name__, template_folder="../templates", static_folder="../static")

FATMA_NODE_URL = "http://127.0.0.1:5862/receive"
YOUSSEF_NODE_URL = "http://127.0.0.1:5873/receive"
inbox_messages = []
K_pub_key, K_prv_key = request_key()
F_key, Y_key = None, None
sent_my_key_to_F, sent_my_key_to_Y = False, False
@app.route("/", methods=["GET", "POST"])
def home():
    global sent_my_key_to_F, sent_my_key_to_Y
    status = ""


    if request.method == "POST":
        msg = request.form.get("msg")

        if F_key is None and Y_key is None: status = "Can't comunicate with Fatma neither Youssef right now. "
        else:
            if F_key is None:
                status = "Can't comunicate with Fatma right now She's offline"
            else:
                enc_msg = rsa_enc(msg, F_key)
                #print(f"enc_msg: {enc_msg}")
                payload = {"type":"message","msg": str(enc_msg), "sender":"Karim"}


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
            
            if Y_key is None:
                status = "Can't comunicate with Youssef right now He's offline"
            else:
                enc_msg = rsa_enc(msg, Y_key)
                #print(f"enc_msg: {enc_msg}")
                payload = {"type":"message","msg": str(enc_msg), "sender":"Karim"}


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
        inbox_messages.append(f"Karim: {msg}")



    if request.method == "GET":
        if sent_my_key_to_F is False:
        
            payload = {"type":"key", "Author":"Karim", "n": K_pub_key[0], "e": K_pub_key[1]}
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
        if sent_my_key_to_Y is False:
            payload = {"type":"key", "Author":"Karim", "n": K_pub_key[0], "e": K_pub_key[1]}
            try:
                requests.post(
                    YOUSSEF_NODE_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=1
                )
                status = "Key sent!"
                sent_my_key_to_Y = True
            except:
                if sent_my_key_to_F is False:
                    status =  "Fatma & Youssef didn't receive the Key"
                else:
                    status =  "Youssef didn't receive the Key"

        print(f"Fatma key: {F_key} \n Youssef key: {Y_key}")

    return render_template("chat.html", inbox=inbox_messages, status=status, sender="Karim", receiver="💎Diamonds")

# RECEIVING (JSON POST)
@app.route("/receive", methods=["POST"])
def receive():
    global F_key, Y_key
    data = request.get_json() # dict
    if data["type"] == "key":
        if data["Author"] == "Fatma":    
            F_key = (data["n"],data["e"])
        else:
            Y_key = (data["n"],data["e"])
    else:
        dec_msg = rsa_dec(int(data["msg"]), K_prv_key)
        inbox_messages.append(f"{data["sender"]}: {dec_msg}")
    return {"status": "received"}


@app.route("/inbox_api")
def inbox_api():
    return {"messages": inbox_messages}


if __name__ == "__main__":
    app.run(port=5863, debug=True)
