import os
import json
import requests
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

# Security: Load API Key from environment variable
# Set it via: export GEMINI_API_KEY='your_key' (Linux/Mac) or setx GEMINI_API_KEY "your_key" (Win)
API_KEY = os.environ.get("GEMINI_API_KEY")

# State management for Agent handshakes
last_signature = None


@app.route('/', defaults={'path': ''}, methods=['POST', 'GET'])
@app.route('/<path:path>', methods=['POST', 'GET'])
def proxy_gemini(path):
    global last_signature

    if not API_KEY:
        return jsonify({"error": "GEMINI_API_KEY environment variable not set"}), 500

    if request.method == 'GET':
        return "Gemini Agent Proxy is running!", 200

    data = request.get_json(force=True, silent=True) or {}

    # --- UPSTREAM: Inject signature for Agent Loops ---
    # Fixes: "Function call is missing a thought_signature"
    if last_signature and "contents" in data:
        for content in data["contents"]:
            if "parts" in content:
                for part in content["parts"]:
                    if isinstance(part, dict) and "functionCall" in part:
                        part["thought_signature"] = last_signature
                        print(f"[*] Injected signature into functionCall")

    # Construct Google API URL
    base_url = "https://generativelanguage.googleapis.com"
    full_path = path if path.startswith("v1") else f"v1beta/{path}"
    url = f"{base_url}/{full_path}?key={API_KEY}"

    try:
        # We use streaming to ensure compatibility with IDE plugins (SSE)
        resp = requests.post(url, json=data, headers={'Content-Type': 'application/json'}, stream=True)

        def generate():
            global last_signature
            for line in resp.iter_lines():
                if line:
                    decoded_line = line.decode('utf-8')

                    # Capture signature from the stream for the next request
                    try:
                        # Handle both raw JSON and SSE "data: " format
                        clean_line = decoded_line.replace("data: ", "").strip()
                        chunk_json = json.loads(clean_line)

                        # Look for thought_signature in candidates
                        candidates = chunk_json.get("candidates", []) if isinstance(chunk_json, dict) else []
                        for cand in candidates:
                            content = cand.get("content", {})
                            sig = content.get("thought_signature") or content.get("thoughtSignature")
                            if sig:
                                last_signature = sig
                                print(f"[+] Captured new signature from stream")
                    except:
                        pass

                    yield decoded_line + "\n"

        return Response(generate(), content_type=resp.headers.get('Content-Type'))

    except Exception as e:
        print(f"[ERR] Proxy Error: {e}")
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    # Defaulting to 5005 as it's less likely to collide with system services
    print("Starting Proxy on http://localhost:5005")
    app.run(host='0.0.0.0', port=5005, debug=False)