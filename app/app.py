from flask import Flask, render_template, request
import re
import subprocess

app = Flask(__name__)

FLAG = "flag{mitigation_first_then_exploit}"


def safe_host(value: str) -> bool:
    """Allow only hostnames/IP-like strings to avoid command injection."""
    return bool(re.fullmatch(r"[A-Za-z0-9.\-]{1,64}", value))


@app.route("/", methods=["GET"])
def index():
    return render_template("index.html")


@app.route("/vuln-ping", methods=["POST"])
def vuln_ping():
    host = request.form.get("host", "")
    # Intentionally vulnerable for beginner pentesters:
    # shell=True + unsanitized user input enables command injection.
    cmd = f"ping -c 1 {host}"
    try:
        output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=3)
        text = output.decode(errors="ignore")
    except Exception as exc:  # noqa: BLE001 - broad by design for challenge readability
        text = str(exc)

    if "BEGINNER_PWNED" in text:
        text += f"\n\nNice! You popped the box. {FLAG}"

    return render_template("result.html", mode="vulnerable", command=cmd, output=text)


@app.route("/safe-ping", methods=["POST"])
def safe_ping():
    host = request.form.get("host", "")

    if not safe_host(host):
        return render_template(
            "result.html",
            mode="mitigated",
            command="blocked",
            output="Blocked: invalid host input. Mitigation works.",
        )

    cmd = ["ping", "-c", "1", host]
    try:
        output = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=3)
        text = output.decode(errors="ignore")
    except Exception as exc:  # noqa: BLE001 - broad by design for challenge readability
        text = str(exc)

    return render_template("result.html", mode="mitigated", command=" ".join(cmd), output=text)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
