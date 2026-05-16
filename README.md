# Information Security Cipher Lab

A VS Code runnable Information Security project with a Python Flask backend and modern dark Gen-Z frontend.

## Features

- Caesar Cipher encryption/decryption with mathematical steps
- Affine Cipher encryption/decryption with modular inverse solution
- Vigenere Cipher encryption/decryption with key table
- Monoalphabetic Substitution Cipher encryption/decryption
- RSA educational encryption/decryption with p, q, n, phi, e, d calculations
- DSA digital signature sign/verify with full math steps
- ASA/AES option using local AES-128-CBC through PyCryptodome
- Offline AI-style explanation module
- Optional local Ollama LLM support without any cloud API key
- HCI-friendly dark UI: clear labels, feedback, consistency, responsive layout, error prevention

## Important Note

DSA is not an encryption algorithm. It is used for digital signatures. That is why this app shows Sign and Verify actions for DSA.

ASA is implemented as AES-style symmetric encryption because many students write ASA when they mean AES.

## How to run in VS Code

1. Open this folder in VS Code.
2. Open terminal in VS Code.
3. Create virtual environment:

```bash
python -m venv venv
```

4. Activate virtual environment:

Windows PowerShell:

```bash
venv\Scripts\activate
```

If activation is blocked, run PowerShell as Administrator and use:

```bash
Set-ExecutionPolicy RemoteSigned
```

Then activate again.

5. Install requirements:

```bash
pip install -r requirements.txt
```

6. Run the app:

```bash
python app.py
```

7. Open browser:

```text
http://127.0.0.1:5000
```

## Optional Local LLM using Ollama

The project runs without any API key. If you have Ollama installed locally, you can enable local LLM explanations:

Windows PowerShell:

```bash
$env:LOCAL_LLM_PROVIDER="ollama"
$env:LOCAL_LLM_MODEL="llama3.2"
python app.py
```

Make sure Ollama is running on your laptop. If Ollama is not running, the app automatically uses the built-in offline explanation engine.

## Default test keys

- Caesar shift: `3`
- Affine: `a=5`, `b=8`
- Vigenere key: `KEY`
- Substitution key: `QWERTYUIOPASDFGHJKLZXCVBNM`
- RSA: `p=61`, `q=53`, `e=17`
- DSA: `p=59`, `q=29`, `g=4`, `x=5`, `k=7`
- ASA/AES key: `information-security-key`

## Project type

This is an educational project for Information Security. Do not use the small-number RSA/DSA settings for real security.
