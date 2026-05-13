"""
1. On first GET, Bob sends his ECC public key to Alice2.
2. Alice2's public key arrives via /receive.
3. All subsequent messages are ECIES-encrypted bundles.
"""

import requests
from flask import Flask, render_template, request

from crypto.ECC   import generate_keypair, public_key_to_hex
from crypto.ECIES import ecies_encrypt, ecies_decrypt, bundle_to_hex, bundle_from_hex

app = Flask(__name__)

# --------- Network ---------
NODE_A_URL = "http://127.0.0.1:5001/receive"

# --------- State ------------------
inbox_messages = []
B_priv, B_pub = generate_keypair()
A_pub          = None        
sent_my_key    = False


# ----------------------------
#  Routes
# ----------------------------

@app.route("/", methods=["GET", "POST"])
def home():
    global sent_my_key, A_pub
    status = ""

    # --------- SEND public key once on first visit ------------------------------
    if request.method == "GET" and not sent_my_key:
        bx, by = B_pub
        payload = {"type": "B_pub", "x": bx, "y": by}
        try:
            requests.post(NODE_A_URL, json=payload,
                          headers={"Content-Type": "application/json"}, timeout=5)
            status      = "Bob's ECC public key sent to Alice2."
            sent_my_key = True
        except Exception:
            status = "Alice2 is offline — couldn't send public key."

    # --------- SEND encrypted message ---------------------------------------
    if request.method == "POST":
        if A_pub is None:
            status = "Waiting for Alice2's public key — try again in a moment."
        else:
            msg = request.form.get("msg", "")
            # ECIES: encrypt for Alice2 using Alice2's public key
            bundle     = ecies_encrypt(msg.encode(), A_pub)
            hex_bundle = bundle_to_hex(bundle)

            payload = {"type": "message", "bundle": hex_bundle}
            try:
                requests.post(NODE_A_URL, json=payload,
                              headers={"Content-Type": "application/json"}, timeout=5)
                status = "Message sent (ECIES encrypted)."
                inbox_messages.append(f"Bob: {msg}")
            except Exception:
                status = "Alice2 didn't receive the message."

    return render_template("chat.html",
                           inbox=inbox_messages,
                           status=status,
                           sender="Bob",
                           receiver="Alice2")


@app.route("/receive", methods=["POST"])
def receive():
    global A_pub
    data = request.get_json()

    if data["type"] == "A_pub":
        A_pub = (data["x"], data["y"])

    elif data["type"] == "message":
        bundle    = bundle_from_hex(data["bundle"])
        plaintext = ecies_decrypt(bundle, B_priv)
        inbox_messages.append(f"Alice2: {plaintext.decode()}")

    return {"status": "received"}


@app.route("/inbox_api")
def inbox_api():
    return {"messages": inbox_messages}


@app.route("/pubkey")
def pubkey():
    return {"owner": "Bob", "pubkey_hex": public_key_to_hex(B_pub)}


if __name__ == "__main__":
    app.run(port=5002, debug=True)