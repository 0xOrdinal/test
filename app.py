import requests
import base58
from solders.keypair import Keypair
from datetime import datetime
from dotenv import load_dotenv
import os
import time
import threading
from flask import Flask

# Load environment variables
load_dotenv()

# Solana private key and session signature from environment variables
private_key_b58 = os.getenv("PV_KEY", "")  # Private key in base58
allo_wallet = os.getenv("ALLOCATION_WALLET", "")
claim_wallet = os.getenv("CLAIM_WALLET", "")
url = "https://mefoundation.com/api/trpc/auth.linkWallet?batch=1"

# Decode base58 to obtain raw private key bytes (64 bytes expected)
private_key = base58.b58decode(private_key_b58)
if len(private_key) != 64:
    raise ValueError("Private key must be 64 bytes long!")

# Create Solana Keypair from decoded private key bytes
keypair = Keypair.from_bytes(private_key)

# Flask app setup
app = Flask(__name__)

# State variables to manage the background task
is_running = False
task_thread = None

# Function to sign the message using Solana private key
def sign_message(message: str, keypair: Keypair) -> str:
    message_bytes = message.encode('utf-8')
    sign = keypair.sign_message(message_bytes)  # Use the correct sign_message method
    return base58.b58encode(bytes(sign)).decode('utf-8')  # Convert signature to bytes explicitly

# Generate dynamic timestamp
def create_message(issued_at=datetime.utcnow().isoformat() + "Z"):
    message = (
        f"URI: mefoundation.com\n"
        f"Issued At: {issued_at}\n"
        f"Chain ID: sol\n"
        f"Allocation Wallet: {allo_wallet}\n"
        f"Claim Wallet:{claim_wallet} "
    )
    return message

# Create the payload for the POST request
def create_payload(message, signature):
    payload = {
        "0": {
            "json": {
                "message": message,
                "wallet": f"{allo_wallet}",
                "chain": "sol",
                "signature": signature,
                "allocationEvent": "tge-airdrop-final",
                "isLedger": False,
            }
        }
    }
    return payload

# Function that will be run in a background thread to send requests continuously
def process_message():
    while is_running:
        # Create a dynamic message and signature
        message = create_message()
        signature = sign_message(message, keypair)
        payload = create_payload(message, signature)

        # Send the POST request
        response = requests.post(url, json=payload)
        print(f"Status Code: {response.status_code}")
        print(f"Response: {response.text}")
        
        # Sleep for 30 seconds before the next iteration (you can change this)
        #time.sleep(30)

# Endpoint to start the process
@app.route('/start', methods=['GET'])
def start_sending_requests():
    global is_running, task_thread
    
    if not is_running:
        is_running = True
        task_thread = threading.Thread(target=process_message)
        task_thread1 = threading.Thread(target=process_message)
        task_thread.start()
        task_thread1.start()
        
        return "Started sending requests.", 200
    else:
        return "Already sending requests.", 400

# Endpoint to stop the process
@app.route('/stop', methods=['GET'])
def stop_sending_requests():
    global is_running, task_thread
    
    if is_running:
        is_running = False
        task_thread.join()  # Wait for the thread to finish cleanly
        return "Stopped sending requests.", 200
    else:
        return "No active request sending process.", 400

if __name__ == "__main__":
    # Run Flask app (you can specify host='0.0.0.0' for external access)
    app.run(debug=True, host='0.0.0.0', port=5000)
