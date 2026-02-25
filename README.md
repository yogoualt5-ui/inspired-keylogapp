# Beginner Mitigation Attack Box (CTF-style)

A tiny intentionally vulnerable web box for beginner pentesters.

## What you practice
- Spotting command injection in Python (`shell=True` with user input).
- Exploiting it safely in a local lab.
- Comparing with a mitigated version (allowlist validation + no shell invocation).

## Run locally
```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app/app.py
```
Then open `http://localhost:5000`.

## Run in Docker
```bash
docker build -t beginner-attack-box .
docker run --rm -p 5000:5000 beginner-attack-box
```

## Challenge flow
1. Send a normal host (e.g., `127.0.0.1`) to both forms and observe behavior.
2. Attack `/vuln-ping` with payload like:
   - `127.0.0.1; echo BEGINNER_PWNED`
3. Find the flag in the vulnerable output.
4. Reuse the payload on `/safe-ping` and confirm it is blocked.
5. Explain mitigation:
   - input allowlist (`[A-Za-z0-9.-]`)
   - argument list passed to `subprocess` with no shell.

## Important
This lab is intentionally insecure. Use only in your own environment.
