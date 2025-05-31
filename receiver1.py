import os
import time
import hmac
import hashlib
from flask import Flask, request, abort, send_file
from dotenv import load_dotenv

# Load environment variables
load_dotenv()
API_KEY = os.getenv("API_KEY")
SERVER_SECRET = os.getenv("SERVER_SECRET")

app = Flask(__name__)
SAVE_DIR = "received_logs"
COMBINED_LOG = os.path.join(SAVE_DIR, "combined.log")

# Create log directory
os.makedirs(SAVE_DIR, exist_ok=True)

def verify_request(request):
    """Verify API key and HMAC signature"""
    # Get headers
    api_key = request.headers.get('X-API-Key')
    signature = request.headers.get('X-Signature')
    timestamp = request.headers.get('X-Timestamp')
    
    # Check if headers exist
    if not api_key or not signature or not timestamp:
        return False, "Missing security headers"
    
    # Verify API key
    if api_key != API_KEY:
        return False, "Invalid API key"
    
    # Check timestamp (within 2 minutes)
    try:
        current_time = time.time()
        if abs(current_time - float(timestamp)) > 120:
            return False, "Expired timestamp"
    except ValueError:
        return False, "Invalid timestamp"
    
    # Get file data
    if 'logfile' not in request.files:
        return False, "No logfile provided"
    
    file = request.files['logfile']
    data = file.read().decode('utf-8', errors='ignore')
    
    # Verify HMAC signature
    expected_sig = hmac.new(
        SERVER_SECRET.encode(),
        data.encode() + timestamp.encode(),
        hashlib.sha256
    ).hexdigest()
    
    if not hmac.compare_digest(signature, expected_sig):
        return False, "Invalid signature"
    
    return True, data

@app.route('/upload', methods=['POST'])
def upload():
    # Verify request
    valid, message = verify_request(request)
    if not valid:
        print(f"[!] Upload rejected: {message}")
        abort(401, description=message)
    
    # Get data from verification
    data = message  # In this case, message is the data
    
    # Save to log
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(COMBINED_LOG, "a", encoding="utf-8") as log:
            log.write(f"\n--- {timestamp} ---\n{data}")
        print(f"[+] Received {len(data)} bytes of data")
        return "OK", 200
    except Exception as e:
        print(f"[!] Error saving log: {str(e)}")
        return "Server error", 500

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)