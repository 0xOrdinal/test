import requests
import base58
from solders.keypair import Keypair
from datetime import datetime
from dotenv import load_dotenv
import os
import time

# Load environment variables
load_dotenv()

# Solana private key and session signature from environment variables
private_key_b58 = os.getenv("PV_KEY", "")  # Private key in base58
session_signature_value = os.getenv("SIGNATURE", "")
allo_wallet=os.getenv("ALLOCATION_WALLET", "")
claim_wallet=os.getenv("CLAIM_WALLET", "")
url = "https://mefoundation.com/api/trpc/auth.linkWallet?batch=1"
cookies = {"session_signature": session_signature_value}
headers = {"Content-Type": "application/json"}

# Decode base58 to obtain raw private key bytes (64 bytes expected)
private_key = base58.b58decode(private_key_b58)
if len(private_key) != 64:
    raise ValueError("Private key must be 64 bytes long!")

# Create Solana Keypair from decoded private key bytes
keypair = Keypair.from_bytes(private_key)

# Function to sign the message using Solana private key
def sign_message(message: str, keypair: Keypair) -> str:
    message_bytes = message.encode('utf-8')
    sign = keypair.sign_message(message_bytes)  # Use the correct sign_message method
    return base58.b58encode(bytes(sign)).decode('utf-8')  # Convert signature to bytes explicitly

# Generate dynamic timestamp

# Construct the dynamic message
def create_message(issued_at=datetime.utcnow().isoformat() + "Z"):
    message = (
    f"URI: mefoundation.com\n"
    f"Issued At: {issued_at}\n"
    f"Chain ID: sol\n"
    f"Allocation Wallet: {allo_wallet}\n"
    f"Claim Wallet:{claim_wallet} "
    )
    return message
def create_payload(message,signature):
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



while(True):
    message=create_message()
    signature = sign_message(message, keypair)
    payload=create_payload(message,signature)
    response = requests.post(url, json=payload)
    print(f"Status Code: {response.status_code}")
    print(f"Response: {response.text}")
    #time.sleep(30)