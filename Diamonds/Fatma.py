from flask import Flask, request, render_template
import requests
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from crypto.rsa.rsatest import request_key, rsa_test, rsa_enc, rsa_dec
app = Flask(__name__, template_folder="../templates", static_folder="../static")

KARIM_NODE_URL = "http://127.0.0.1:5863/receive"
YOUSSEF_NODE_URL = "http://127.0.0.1:5873/receive"
inbox_messages = []
F_pub_key, F_prv_key = request_key()
K_key, Y_key = None, None
sent_my_key_to_k, sent_my_key_to_Y = False, False
@app.route("/", methods=["GET", "POST"])
def home():
    global sent_my_key_to_k, sent_my_key_to_Y
    status = ""


    if request.method == "POST":
        msg = request.form.get("msg")
        
        if K_key is None and Y_key is None: status = "Can't comunicate with Karim neither Youssef right now. "
        else:
            if K_key is None:
                status = "Can't comunicate with Karim right now He's offline"
            else:
                enc_msg = rsa_enc(msg, K_key)
                #print(f"enc_msg: {enc_msg}")
                payload = {"type":"message","msg": str(enc_msg), "sender":"Fatma"}


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
                enc_msg = rsa_enc(msg, Y_key)
                #print(f"enc_msg: {enc_msg}")
                payload = {"type":"message","msg": str(enc_msg), "sender":"Fatma"}


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
        if sent_my_key_to_k is False:
        
            payload = {"type":"key", "Author":"Fatma", "n": F_pub_key[0], "e": F_pub_key[1]}
            try:
                requests.post(
                    KARIM_NODE_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=1
                )
                sent_my_key_to_k = True
            except:
                status = "Karim didn't receive the Key"
        if sent_my_key_to_Y is False:
            payload = {"type":"key", "Author":"Fatma", "n": F_pub_key[0], "e": F_pub_key[1]}
            try:
                requests.post(
                    YOUSSEF_NODE_URL,
                    json=payload,
                    headers={"Content-Type": "application/json"},
                    timeout=1
                )
                if sent_my_key_to_k == False:
                    status = "Karim didn't receive the Key"
                else:
                    status = "Key sent!"
                sent_my_key_to_Y = True
            except:
                if sent_my_key_to_k is False:
                    status =  "Karim & Youssef didn't receive the Key"
                else:
                    status =  "Youssef didn't receive the Key"

        print(f"Karim key: {K_key} \n Youssef key: {Y_key}")

    return render_template("chat.html", inbox=inbox_messages, status=status, sender="Fatma", receiver="💎Diamonds")

# RECEIVING (JSON POST)
@app.route("/receive", methods=["POST"])
def receive():
    global K_key, Y_key
    data = request.get_json() # dict
    if data["type"] == "key":
        if data["Author"] == "Karim":    
            K_key = (data["n"],data["e"])
        elif data["Author"] == "Youssef":
            Y_key = (data["n"],data["e"])
    else:
        dec_msg = rsa_dec(int(data["msg"]), F_prv_key)
        inbox_messages.append(f"{data["sender"]}: {dec_msg}")
    return {"status": "received"}


@app.route("/inbox_api")
def inbox_api():
    return {"messages": inbox_messages}


if __name__ == "__main__":
    app.run(port=5862, debug=True)
