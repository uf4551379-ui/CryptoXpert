"""
Offline explanation layer.

The app does not call paid/cloud APIs. If the user has Ollama running locally,
set LOCAL_LLM_PROVIDER=ollama and LOCAL_LLM_MODEL=llama3.2 to get local LLM text.
Otherwise it uses a deterministic built-in tutor that behaves like a mini teaching
assistant for cipher explanations.
"""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any, Dict, List


def _ollama_generate(prompt: str) -> str | None:
    if os.getenv("LOCAL_LLM_PROVIDER", "").lower() != "ollama":
        return None
    model = os.getenv("LOCAL_LLM_MODEL", "llama3.2")
    payload = json.dumps({
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {"temperature": 0.2}
    }).encode("utf-8")
    try:
        request = urllib.request.Request(
            "http://localhost:11434/api/generate",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=5) as response:
            data = json.loads(response.read().decode("utf-8"))
            return data.get("response")
    except Exception:
        return None


def build_explanation(cipher: str, action: str, text: str, result: str, steps: List[str], meta: Dict[str, Any]) -> str:
    prompt = f"""
Explain this Information Security result in easy English for a student.
Cipher: {cipher}
Action: {action}
Input: {text[:300]}
Result: {result[:300]}
Mathematical steps: {steps[:8]}
Metadata: {meta}
Keep it short, clear, and exam-friendly.
""".strip()
    local_llm = _ollama_generate(prompt)
    if local_llm:
        return local_llm.strip()

    cipher_name = meta.get("cipher", cipher).upper()
    action_word = action.lower()
    intro = f"This result was produced using {cipher_name}. The app first converts the input into mathematical values, then applies the selected {action_word} formula."
    if cipher.lower() == "dsa":
        intro = "DSA is a digital signature method, so it does not encrypt text. It proves that a message is authentic by creating or verifying a signature."
    elif cipher.lower() in {"asa", "aes", "asa_aes"}:
        intro = "ASA is handled as an AES-style symmetric encryption option. The same secret key is used to encrypt and decrypt the message locally."

    important = " ".join(steps[:4])
    conclusion = "The mathematical steps shown below are the main part to write in your assignment or explain in viva."
    return f"{intro}\n\nKey idea: {important}\n\n{conclusion}"
