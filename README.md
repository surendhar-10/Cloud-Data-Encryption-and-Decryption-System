# Cloud Data Encryption and Decryption System

A runnable college-project starter using Python Flask, SQLite, and AES-256-GCM.

## Features
- User registration and login
- Password hashing for account credentials
- Encrypt files before saving them in the local `cloud_storage/` folder
- AES-256-GCM authenticated encryption (detects tampering)
- Per-file key derivation using scrypt and a random salt
- User-specific file listing and download/decryption
- Responsive web interface

## Requirements
- Python 3.10+
- Windows, macOS, or Linux

## Run on Windows PowerShell
```powershell
cd cloud_data_encryption_system
py -m venv venv
.\venv\Scripts\Activate.ps1
pip install -r requirements.txt
python app.py
```
If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass` in that terminal, then activate again. Alternatively, use `venv\Scripts\python.exe -m pip install -r requirements.txt` and `venv\Scripts\python.exe app.py`.

Open http://127.0.0.1:5000 and register an account.

## Run on macOS/Linux
```bash
cd cloud_data_encryption_system
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Important security notes
- This starter simulates cloud storage locally; it does not connect to AWS or Firebase yet.
- The file encryption password is never stored. If you forget it, the encrypted file cannot be decrypted.
- Keep `FLASK_SECRET_KEY` secret and replace the development fallback before deployment.
- `debug=True` is for local development only. Turn it off and use HTTPS plus a production WSGI server before deployment.
- For a production cloud deployment, add managed key storage (such as AWS KMS), authorization/CSRF protections, rate limiting, backups, and secure audit logging.
- Do not upload highly sensitive real-world data to this learning/demo app.
