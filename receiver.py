import os, time
from flask import Flask, request, send_file
from flask_httpauth import HTTPBasicAuth
import bcrypt
from dotenv import load_dotenv  # Add this import

# Load environment variables first
load_dotenv()  # Add this line

app = Flask(__name__)
SAVE_DIR       = os.path.expanduser("~/received_logs")
COMBINED_LOG   = os.path.join(SAVE_DIR, "received_combined.log")

# Ensure directory exists
os.makedirs(SAVE_DIR, exist_ok=True)

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('logfile')
    if not f:
        return "No logfile", 400

    # Read the uploaded data
    data = f.read().decode('utf-8', errors='ignore')

    # Append to one combined log file with a timestamp header
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(COMBINED_LOG, "a", encoding="utf-8") as log:
        log.write(f"\n--- Received at {timestamp} ---\n")
        log.write(data)
        log.flush()

    print(f"[+] Appended upload at {timestamp} (size: {len(data)} bytes)")
    return "OK", 200

# ─── PASSWORD PROTECTED LOG VIEWING ─────────────────────────────────────────────
auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    # Verify admin credentials
    if username == "admin":
        # Get hashed password from environment
        hashed_password = os.getenv("ADMIN_PASSWORD", "").encode()
        if hashed_password:
            try:
                return bcrypt.checkpw(password.encode(), hashed_password)
            except:
                return False
    return False

@app.route('/logs')
@auth.login_required
def view_logs():
    try:
        return send_file(COMBINED_LOG, mimetype='text/plain')
    except FileNotFoundError:
        return "Log file not found", 404

if __name__ == "__main__":
    # Debug: Show environment status
    print("Server starting with configuration:")
    print(f"ADMIN_PASSWORD set: {'Yes' if os.getenv('ADMIN_PASSWORD') else 'No'}")
    
    app.run(host="0.0.0.0", port=5000, debug=True)