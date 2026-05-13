""""
1. On first GET, Alice2 sends her ECC public key to Bob2.
2. Bob2 replies with his ECC public key (via /receive).
3. Once both sides have each other's public key, every
   message is encrypted with ecies_encrypt(msg, peer_pub).
4. Receiver calls ecies_decrypt(bundle, own_priv) to read it.
"""

import requests
from flask import Flask, render_template, request

from crypto.ECC   import generate_keypair, public_key_to_hex
from crypto.ECIES import ecies_encrypt, ecies_decrypt, bundle_to_hex, bundle_from_hex

app = Flask(__name__)

# --------- Network -----------------------------------
NODE_B_URL = "http://127.0.0.1:5002/receive"

# --------- State ----------------------------------------
inbox_messages = []

A_priv, A_pub = generate_keypair()
B_pub          = None       
sent_my_key    = False


# ----------------------------------------
#  Routes
#------------------------------------

@app.route("/", methods=["GET", "POST"])
def home():
    global sent_my_key, B_pub
    status = ""

    
    if request.method == "GET" and not sent_my_key:
        ax, ay = A_pub
        payload = {"type": "A_pub", "x": ax, "y": ay}
        try:
            requests.post(NODE_B_URL, json=payload,
                          headers={"Content-Type": "application/json"}, timeout=5)
            status        = "Alice2's ECC public key sent to Bob2."
            sent_my_key   = True
        except Exception:
            status = "Bob2 is offline — couldn't send public key."

    # --------- SEND encrypted message -------------------------------------
    if request.method == "POST":
        if B_pub is None:
            status = "Waiting for Bob2's public key — try again in a moment."
        else:
            msg = request.form.get("msg", "")
            # ECIES: encrypt for Bob2 using Bob2's public key
            bundle     = ecies_encrypt(msg.encode(), B_pub)
            hex_bundle = bundle_to_hex(bundle)

            payload = {"type": "message", "bundle": hex_bundle}
            try:
                requests.post(NODE_B_URL, json=payload,
                              headers={"Content-Type": "application/json"}, timeout=5)
                status = "Message sent (ECIES encrypted)."
                inbox_messages.append(f"Alice2: {msg}")
            except Exception:
                status = "Bob2 didn't receive the message."

    return render_template("chat.html",
                           inbox=inbox_messages,
                           status=status,
                           sender="Alice2",
                           receiver="Bob2")


@app.route("/receive", methods=["POST"])
def receive():
    global B_pub
    data = request.get_json()

    if data["type"] == "B_pub":
        B_pub = (data["x"], data["y"])

    elif data["type"] == "message":
        bundle    = bundle_from_hex(data["bundle"])
        plaintext = ecies_decrypt(bundle, A_priv)
        inbox_messages.append(f"Bob2: {plaintext.decode()}")

    return {"status": "received"}


@app.route("/inbox_api")
def inbox_api():
    return {"messages": inbox_messages}


@app.route("/pubkey")
def pubkey():
    """Expose Alice2's public key as JSON (for debugging / inspection)."""
    return {"owner": "Alice2", "pubkey_hex": public_key_to_hex(A_pub)}


if __name__ == "__main__":
    app.run(port=5001, debug=True)