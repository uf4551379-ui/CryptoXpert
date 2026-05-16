from __future__ import annotations

from flask import Flask, jsonify, render_template, request

from crypto_engine import CryptoError, process_cipher
from local_llm_explainer import build_explanation

app = Flask(__name__)


@app.route("/")
def home():
    return render_template("index.html")


@app.post("/api/process")
def process():
    data = request.get_json(silent=True) or {}
    cipher = data.get("cipher", "caesar")
    action = data.get("action", "encrypt")
    text = data.get("text", "")
    keys = data.get("keys", {}) or {}

    try:
        response = process_cipher(cipher, action, text, keys)
        explanation = build_explanation(cipher, action, text, response.result, response.steps, response.meta)
        return jsonify({
            "ok": True,
            "result": response.result,
            "steps": response.steps,
            "table": response.table,
            "warnings": response.warnings,
            "meta": response.meta,
            "ai_explanation": explanation,
        })
    except CryptoError as exc:
        return jsonify({"ok": False, "error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"ok": False, "error": f"Unexpected error: {exc}"}), 500


@app.get("/api/health")
def health():
    return jsonify({"ok": True, "message": "Information Security Cipher Lab is running."})


if __name__ == "__main__":
    app.run(debug=True, host="127.0.0.1", port=5000)
