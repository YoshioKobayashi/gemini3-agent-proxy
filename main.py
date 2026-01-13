import os
import json
import requests
import hashlib
import time
from flask import Flask, request, Response, stream_with_context

app = Flask(__name__)

# --- KONFIGURATION ---
API_KEY = os.environ.get("GEMINI_API_KEY", "")
STORE_FILE = "signatures.json"
DEBUG_DIR = "debug_dumps"
DEFAULT_API_VERSION = "v1beta"
if not os.path.exists(DEBUG_DIR):
    os.makedirs(DEBUG_DIR)

def save_debug_file(prefix, data, is_json=True):
    """Speichert detaillierte Dumps für das Debugging."""
    timestamp = int(time.time() * 1000)
    ext = "json" if is_json else "txt"
    filename = f"{prefix}_{timestamp}.{ext}"
    filepath = os.path.join(DEBUG_DIR, filename)
    try:
        with open(filepath, "w", encoding="utf-8") as f:
            if is_json:
                json.dump(data, f, indent=2, ensure_ascii=False)
            else:
                f.write(data)
    except Exception as e:
        print(f"[!] Debug save error: {e}")

def load_store():
    """Lädt die gespeicherten Signaturen beim Start."""
    if os.path.exists(STORE_FILE):
        try:
            with open(STORE_FILE, "r", encoding="utf-8") as f:
                store = json.load(f)
                print(f"[*] {len(store)} Signaturen geladen.")
                return store
        except Exception as e:
            print(f"[!] Fehler beim Laden: {e}")
    return {}

def save_store(store):
    """Speichert Signaturen permanent."""
    try:
        with open(STORE_FILE, "w", encoding="utf-8") as f:
            json.dump(store, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"[!] Fehler beim Speichern: {e}")

signature_store = load_store()

def get_call_hash(function_name, function_args):
    """Berechnet einen eindeutigen Hash. Achtung: Payload muss konsistent sein!"""
    try:
        name = (function_name or "").strip().split(":")[-1]
        args_str = json.dumps(function_args or {}, sort_keys=True, ensure_ascii=False)
        # Dieser Payload muss exakt gleich bleiben zwischen lernen und injizieren
        payload = f"{name}::{args_str}"
        return hashlib.md5(payload.encode()).hexdigest()
    except Exception as e:
        print(f"[!] Hash error: {e}")
        return None

# --- EXTRAKTION & INJEKTION ---
def learn_signatures_recursive(obj):
    """Durchsucht rekursiv nach 'thought_signature' und speichert sie."""
    found = False
    if isinstance(obj, dict):
        if "functionCall" in obj and "thought_signature" in obj["functionCall"]:
            fc = obj["functionCall"]
            c_hash = get_call_hash(fc.get("name"), fc.get("args"))
            if c_hash and c_hash not in signature_store:
                signature_store[c_hash] = fc["thought_signature"]
                print(f"[✓] GEWONNEN: Signatur für '{fc.get('name')}' gelernt (Hash: {c_hash[:8]})")
                found = True
        for v in obj.values():
            if learn_signatures_recursive(v): found = True
    elif isinstance(obj, list):
        for item in obj:
            if learn_signatures_recursive(item): found = True
    return found

def inject_signatures(req_data):
    """Fügt fehlende Signaturen in den Request-Verlauf ein."""
    if not req_data or "contents" not in req_data:
        return req_data
    for content in req_data.get("contents", []):
        if content.get("role") == "model":
            for part in content.get("parts", []):
                if "functionCall" in part:
                    fc = part["functionCall"]
                    if "thought_signature" not in fc:
                        name = fc.get("name")
                        c_hash = get_call_hash(name, fc.get("args"))
                        if c_hash in signature_store:
                            fc["thought_signature"] = signature_store[c_hash]
                            print(f"[✓] Signatur für '{name}' injiziert.")
                        else:
                            print(f"[!] Signatur für '{name}' fehlt (Hash: {c_hash[:8] if c_hash else 'N/A'})")
    return req_data

@app.route('/', defaults={'path': ''}, methods=['GET', 'POST', 'PUT', 'DELETE'])
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    # URL zusammenbauen
    final_path = path if path.startswith("v") else f"{DEFAULT_API_VERSION}/{path}"
    url = f"https://generativelanguage.googleapis.com/{final_path}?key={API_KEY}"
    
    # Request Body verarbeiten
    req_data = request.get_json(force=True, silent=True)
    if req_data:
        req_data = inject_signatures(req_data)
    
    save_debug_file("req_out", req_data)
    
    # Headers vorbereiten
    headers = {k: v for k, v in request.headers.items()
               if k.lower() not in ['host', 'content-length', 'accept-encoding']}
    
    try:
        resp = requests.request(
            method=request.method,
            url=url,
            headers=headers,
            json=req_data,
            stream=True,
            timeout=120
        )
        
        if resp.status_code >= 400:
            error_text = resp.text
            save_debug_file("err_google_response", {"status": resp.status_code, "text": error_text})
            print(f"[!] API Error {resp.status_code}")
            return Response(error_text, status=resp.status_code, content_type='application/json')
        
        @stream_with_context
        def generate():
            full_response_body = ""
            # Stream an den Client weitergeben und parallel aufzeichnen
            for chunk in resp.iter_content(chunk_size=4096, decode_unicode=True):
                if chunk:
                    yield chunk
                    full_response_body += chunk
            
            # --- BLACKBOX-ANALYSE NACH DEM STREAM ---
            print("[i] Stream beendet. Analysiere komplette Antwort...")
            save_debug_file("resp_full_raw", full_response_body, is_json=False)

            # Bereinige den Text von SSE-Präfixen etc.
            clean_body = full_response_body.replace("data:", "").strip()
            # Manchmal ist es ein Array von Objekten, manchmal nur ein Objekt
            if not clean_body.startswith("["):
                clean_body = f"[{clean_body}]" # Erzwinge Array-Struktur
            
            try:
                # Versuche, das gesamte Dokument als JSON-Array zu parsen
                parsed_json = json.loads(clean_body)
                if learn_signatures_recursive(parsed_json):
                    save_store(signature_store) # Speichern, wenn was gelernt wurde
                    print("[i] Analyse erfolgreich, Signatur(en) gespeichert.")
                else:
                    print("[!] Analyse beendet. KEINE Signatur in der Antwort gefunden.")
            except json.JSONDecodeError as e:
                print(f"[!] FATAL: Komplette Antwort ist kein valides JSON. Fehler: {e}")

        
        out_headers = {k: v for k, v in resp.headers.items()
                       if k.lower() not in ['content-encoding', 'content-length', 
                                           'transfer-encoding', 'connection']}
        
        return Response(generate(), status=resp.status_code, headers=out_headers,
                        content_type=resp.headers.get('Content-Type'))
        
    except Exception as e:
        print(f"[!] Proxy-Fehler: {e}")
        return Response(json.dumps({"error": str(e)}), status=500, content_type='application/json')

if __name__ == '__main__':
    print(f"[*] Gemini Proxy läuft auf Port 5005")
    app.run(host='0.0.0.0', port=5005, threaded=True, use_reloader=False)