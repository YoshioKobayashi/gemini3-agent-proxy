import os
import json
import requests
import hashlib
from flask import Flask, request, jsonify, Response, stream_with_context

app = Flask(__name__)

API_KEY = os.environ.get("GEMINI_API_KEY")
TARGET_MODEL = "gemini-2.0-flash-exp"

# Hash(FunctionName + Args) -> Thought_Signature
signature_store = {}


# ---------- Hilfsfunktionen: robustes JSON & Hashing ----------

def safe_json_loads(s):
    """Versucht JSON zu parsen, gibt bei Fehlern None zurück."""
    try:
        return json.loads(s)
    except Exception:
        return None


def get_call_hash(function_name, function_args):
    """Erzeugt einen stabilen Hash für einen Funktionsaufruf."""
    try:
        if isinstance(function_args, str):
            try:
                function_args = json.loads(function_args)
            except Exception:
                pass

        args_str = json.dumps(function_args, sort_keys=True, ensure_ascii=False)
        unique_string = f"{function_name}::{args_str}"
        return hashlib.md5(unique_string.encode("utf-8")).hexdigest()
    except Exception as e:
        print(f"[!] Hash Error: {e}")
        return None


# ---------- Robust: candidates / parts / content traversieren ----------

def extract_candidates(obj):
    """
    Holt rekursiv alle 'candidates' aus einem JSON-Objekt,
    egal ob es Dict, List oder verschachtelt ist.
    """
    result = []

    if isinstance(obj, dict):
        if "candidates" in obj and isinstance(obj["candidates"], list):
            result.extend(obj["candidates"])
        # zusätzlich rekursiv über alle Values laufen
        for v in obj.values():
            result.extend(extract_candidates(v))

    elif isinstance(obj, list):
        for item in obj:
            result.extend(extract_candidates(item))

    return result


def iter_parts_from_candidate(candidate):
    """
    Iteriert robust über alle parts eines candidates.
    candidate kann Dict oder List sein, content kann Dict oder List sein,
    parts kann Dict oder List sein.
    """
    # Falls candidate eine Liste ist, rekursiv über alle Elemente
    if isinstance(candidate, list):
        for c in candidate:
            yield from iter_parts_from_candidate(c)
        return

    if not isinstance(candidate, dict):
        return

    content = candidate.get("content", [])
    if isinstance(content, dict):
        content = [content]
    elif not isinstance(content, list):
        return

    for c in content:
        if not isinstance(c, dict):
            continue
        parts = c.get("parts", [])
        if isinstance(parts, dict):
            parts = [parts]
        elif not isinstance(parts, list):
            continue

        for p in parts:
            if isinstance(p, dict):
                yield p


# ---------- Signaturen injizieren (vor Request) ----------

def inject_signatures(data):
    """
    Durchläuft die Request-History und ergänzt fehlende thought_signatures
    bei bekannten FunctionCalls.
    """
    if not isinstance(data, dict):
        return 0

    contents = data.get("contents")
    if not isinstance(contents, list):
        return 0

    restored_count = 0

    for content in contents:
        if not isinstance(content, dict):
            continue

        # Wir suchen nur in Model-Antworten der History
        if content.get("role") != "model":
            continue

        parts = content.get("parts", [])
        if isinstance(parts, dict):
            parts = [parts]
        if not isinstance(parts, list):
            continue

        for part in parts:
            if not isinstance(part, dict):
                continue

            if "functionCall" in part and not part.get("thought_signature"):
                fc = part["functionCall"]
                if not isinstance(fc, dict):
                    continue

                f_name = fc.get("name")
                f_args = fc.get("args", {})

                call_hash = get_call_hash(f_name, f_args)
                if call_hash and call_hash in signature_store:
                    original_sig = signature_store[call_hash]
                    part["thought_signature"] = original_sig
                    part["thoughtSignature"] = original_sig
                    restored_count += 1
                    print(f"[*] 💎 Original-Signatur wiederhergestellt für: {f_name}")
                else:
                    print(f"[!] Warnung: Keine Signatur für {f_name} im Speicher gefunden.")

    return restored_count


# ---------- Signaturen ernten (nach dem Stream) ----------

def harvest_signatures_from_response_body(full_response_buffer):
    """
    Versucht, aus dem kompletten Response-Body Signaturen zu extrahieren
    und im signature_store zu speichern.
    """
    try:
        response_json = safe_json_loads(full_response_buffer)
        if response_json is None:
            print("[!] Konnte Response-JSON nicht parsen (Streaming unvollständig oder kein valides JSON).")
            return

        candidates = extract_candidates(response_json)
        if not candidates:
            print("[*] Keine candidates im Response gefunden.")
            return

        for cand in candidates:
            for part in iter_parts_from_candidate(cand):
                if "functionCall" not in part:
                    continue

                fc = part["functionCall"]
                if not isinstance(fc, dict):
                    continue

                sig = part.get("thought_signature") or part.get("thoughtSignature")
                if not sig:
                    # ToolCall ohne Signatur – kann vorkommen
                    continue

                name = fc.get("name")
                args = fc.get("args", {})

                c_hash = get_call_hash(name, args)
                if not c_hash:
                    continue

                signature_store[c_hash] = sig
                print(f"[*] 💾 Signatur gespeichert für: {name}")

    except Exception as e:
        print(f"[!] Error beim Speichern der Signatur: {e}")


# ---------- Proxy-Route ----------

@app.route('/', defaults={'path': ''}, methods=['POST', 'GET'])
@app.route('/<path:path>', methods=['POST', 'GET'])
def proxy_gemini(path):
    if request.method == 'GET':
        return "Clean Proxy Active.", 200

    data = request.get_json(force=True, silent=True) or {}

    # Vor dem Forwarden: Signaturen in der History injizieren
    inject_signatures(data)

    clean_path = path.replace("v1beta/", "").replace("v1/", "")
    url = f"https://generativelanguage.googleapis.com/v1beta/{clean_path}?key={API_KEY}"

    try:
        resp = requests.post(url, json=data, stream=True, timeout=60)

        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
        headers = {k: v for k, v in resp.headers.items() if k.lower() not in excluded_headers}

        @stream_with_context
        def generate():
            full_response_buffer = ""
            for chunk in resp.iter_content(chunk_size=None):
                if chunk:
                    decoded = chunk.decode('utf-8', errors='ignore')
                    full_response_buffer += decoded
                    yield chunk

            # Nach dem Stream: Signaturen ernten
            harvest_signatures_from_response_body(full_response_buffer)

        return Response(generate(), headers=headers, content_type=resp.headers.get('Content-Type'))

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    print("[*] Clean Proxy läuft auf Port 5005")
    app.run(host='0.0.0.0', port=5005, threaded=True)