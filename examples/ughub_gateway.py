from flask import Flask, request, jsonify
import requests
import jwt
import paho.mqtt.client as mqtt

app = Flask(__name__)

UGUB_TOKEN_URL = "https://iam.ughub.go.ug/token"
UGUB_API_BASE = "https://api.ughub.go.ug"
MQTT_BROKER = "mqtt.ughub.go.ug"
MQTT_PORT = 8883

def get_jwt():
    # Use your client_id/secret from UGHub onboarding
    payload = {
        "grant_type": "client_credentials",
        "client_id": "naashon-secure-iot-app",
        "client_secret": "SUPER_SECRET_FROM_UGHUB"
    }
    r = requests.post(UGUB_TOKEN_URL, data=payload)
    return r.json()["access_token"]

@app.route("/iot/data", methods=["POST"])
def proxy_to_ughub():
    token = get_jwt()
    headers = {"Authorization": f"Bearer {token}"}
    data = request.json
    
    # Forward to your NaashonSecureIoT core (internal)
    internal_resp = requests.post("http://127.0.0.1:5000/internal/ingest", json=data)
    
    # Log to UGHub for compliance
    requests.post(f"{UGUB_API_BASE}/audit/log", headers=headers, json={
        "system": "NaashonSecureIoT",
        "event": "data_ingest",
        "hash": internal_resp.json()["blockchain_hash"]
    })
    
    return jsonify({"status": "compliant_ingest"})

# MQTT client that only connects with UGHub certs
def mqtt_connect():
    client = mqtt.Client(client_id="MTAC-IOT-9001")
    client.tls_set(ca_certs="root-ca.crt")  # from pki.go.ug
    client.username_pw_set("naashon-app", "password-from-ughub")
    client.connect(MQTT_BROKER, MQTT_PORT)
    return client
