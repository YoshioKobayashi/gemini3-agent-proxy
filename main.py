import os
import json
import requests
import hashlib
from flask import Flask, request, jsonify, Response

app = Flask(__name__)

API_KEY = os.environ.get("GEMINI_API_KEY")
HANDSHAKE_MODEL = "gemini-2.5-flash-lite"
signature_cache = {}


def force_handshake():
    if not API_KEY or API_KEY == "asdf":
        return None

    print("[*] 🔄 Erzwinge Signatur-Handshake...")
    # Wir nehmen 1.5-flash-8b oder 2.0-flash-exp, da 2.5 manchmal noch zickt
    model = "gemini-1.5-flash-8b" 
    url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={API_KEY}"
    
    # Wir fügen ein Dummy-Tool hinzu, um die Signatur zu 'erzwingen'
    payload = {
        "contents": [{"role": "user", "parts": [{"text": "Generate signature"}]}],
        "tools": [{"function_declarations": [{"name": "dummy_tool", "description": "Returns dummy data"}]}],
        "generationConfig": {"max_output_tokens": 1}
    }
    
    try:
        r = requests.post(url, json=payload, timeout=3.0)
        if r.status_code == 200:
            res = r.json()
            # Suche tief im JSON nach der Signatur
            candidates = res.get('candidates', [])
            if candidates:
                content = candidates[0].get('content', {})
                sig = content.get('thought_signature') or content.get('thoughtSignature')
                if sig:
                    print(f"[+] ✅ Signatur erhalten: {sig[:10]}...")
                    return sig
        print(f"[!] Handshake lieferte keine Signatur (Status: {r.status_code})")
    except Exception as e:
        print(f"[!] Handshake Exception: {e}")
    return None


def analyze_and_repair(data, conv_key):
    if "contents" not in data: return 0

    has_tool_call = any("functionCall" in str(p) for c in data["contents"] for p in c.get("parts", []))

    if has_tool_call and conv_key not in signature_cache:
        # Wir versuchen es GENAU EINMAL
        new_sig = force_handshake()
        if new_sig:
            signature_cache[conv_key] = new_sig
        else:
            # Falls fehlgeschlagen, setzen wir einen Dummy-Marker,
            # damit wir nicht in eine Endlosschleife laufen
            signature_cache[conv_key] = "PENDING_OR_FAILED"

    repaired_count = 0
    fallback_sig = signature_cache.get(conv_key)
    if fallback_sig == "PENDING_OR_FAILED": fallback_sig = None

    last_sig_in_chain = None
    for i, content in enumerate(data["contents"]):
        for part in content.get("parts", []):
            if not isinstance(part, dict): continue
            if content.get("role") == "model":
                sig = part.get("thought_signature") or part.get("thoughtSignature")
                if sig:
                    last_sig_in_chain = sig
                    signature_cache[conv_key] = sig

            if "functionCall" in part and not part.get("thought_signature"):
                target_sig = last_sig_in_chain or fallback_sig
                if target_sig:
                    part["thought_signature"] = target_sig
                    repaired_count += 1
    return repaired_count


@app.route('/', defaults={'path': ''}, methods=['POST', 'GET'])
@app.route('/<path:path>', methods=['POST', 'GET'])
def proxy_gemini(path):
    # Sofortiger Abbruch wenn kein Key da
    if not API_KEY or API_KEY == "asdf":
        return jsonify({"error": "Bitte setze GEMINI_API_KEY in deiner Shell!"}), 500

    if request.method == 'GET': return "Proxy is up.", 200

    data = request.get_json(force=True, silent=True) or {}
    conv_key = get_conversation_key(data)

    # Analyze & Repair
    analyze_and_repair(data, conv_key)

    clean_path = path.replace("v1beta/", "").replace("v1/", "")
    url = f"https://generativelanguage.googleapis.com/v1beta/{clean_path}?key={API_KEY}"

    try:
        # stream=True ist wichtig, aber wir brauchen auch einen Connect-Timeout
        resp = requests.post(url, json=data, headers={'Content-Type': 'application/json'}, stream=True,
                             timeout=(3.0, 60.0))

        def generate():
            for line in resp.iter_lines():
                if line:
                    decoded = line.decode('utf-8')
                    yield decoded + "\n"
                    # Signaturen im Hintergrund wegspeichern
                    try:
                        clean = decoded.replace("data: ", "").strip()
                        if clean.startswith('{'):
                            chunk = json.loads(clean)
                            for cand in chunk.get("candidates", []):
                                sig = cand.get("content", {}).get("thought_signature")
                                if sig: signature_cache[conv_key] = sig
                    except:
                        pass

        return Response(generate(), content_type=resp.headers.get('Content-Type'))
    except Exception as e:
        print(f"[ERR] {e}")
        return jsonify({"error": str(e)}), 500


def get_conversation_key(data):
    try:
        if "contents" in data and len(data["contents"]) > 0:
            return hashlib.md5(str(data["contents"][0]).encode()).hexdigest()
    except:
        pass
    return "default"


if __name__ == '__main__':
    # Debug=True hilft hier, um zu sehen ob Flask crashed
    app.run(host='0.0.0.0', port=5005, threaded=True, debug=False)