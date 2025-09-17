from flask import Flask, render_template, request, session
import os
import re

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key')  # Change 'dev-secret-key' to something else for local development

# Extended hash info
hash_info = {
    "md5 (raw, 128-bit)": {"hashcat": "0", "john": "raw-md5"},
    "md4 (raw, 128-bit)": {"hashcat": "900", "john": "raw-md4"},
    "md5(md5())": {"hashcat": "60", "john": "-"},
    "md5(sha1())": {"hashcat": "61", "john": "-"},
    "sha-1 (raw, 160-bit)": {"hashcat": "100", "john": "raw-sha1"},
    "sha-224 (raw, 224-bit)": {"hashcat": "6110", "john": "raw-sha224"},
    "sha-256 (raw, 256-bit)": {"hashcat": "1400", "john": "raw-sha256"},
    "sha-384 (raw, 384-bit)": {"hashcat": "10800", "john": "raw-sha384"},
    "sha-512 (raw, 512-bit)": {"hashcat": "1700", "john": "raw-sha512"},
    "whirlpool (raw, 512-bit)": {"hashcat": "6100", "john": "raw-whirlpool"},
    "ntlm (nt hash)": {"hashcat": "1000", "john": "nt"},
    "md5-crypt (unix md5)": {"hashcat": "500", "john": "md5crypt"},
    "sha-256-crypt (unix sha-256)": {"hashcat": "7400", "john": "sha256crypt"},
    "sha-512-crypt (unix sha-512)": {"hashcat": "1800", "john": "sha512crypt"},
    "bcrypt (blowfish-based password hash)": {"hashcat": "3200", "john": "bcrypt"},
    "yescrypt (modern password hash)": {"hashcat": "-", "john": "yescrypt"},
    "cisco ios scrypt": {"hashcat": "-", "john": "cisco-ios-scrypt"},
    "lm hash (LANMAN)": {"hashcat": "3000", "john": "lm"},
    "domain cached creds (MS cache)": {"hashcat": "1100", "john": "mscash"},
}

def identify_hash(hash_str):
    hash_str = hash_str.strip()
    length = len(hash_str)
    hash_lower = hash_str.lower()

    # Crypt-style hashes
    if hash_lower.startswith("$2a$") or hash_lower.startswith("$2b$") or hash_lower.startswith("$2y$"):
        return "bcrypt (blowfish-based password hash)"
    if hash_lower.startswith("$1$"):
        return "md5-crypt (unix md5)"
    if hash_lower.startswith("$5$"):
        return "sha-256-crypt (unix sha-256)"
    if hash_lower.startswith("$6$"):
        return "sha-512-crypt (unix sha-512)"
    if hash_lower.startswith("$y$"):
        return "yescrypt (modern password hash)"
    if hash_lower.startswith("$9$"):
        return "cisco ios scrypt"

    # Hex-only hashes
    if re.fullmatch(r"[0-9a-fA-F]+", hash_str):
        if length == 32:
            return "ntlm (nt hash)"
        elif length == 40:
            return "sha-1 (raw, 160-bit)"
        elif length == 56:
            return "sha-224 (raw, 224-bit)"
        elif length == 64:
            return "sha-256 (raw, 256-bit)"
        elif length == 96:
            return "sha-384 (raw, 384-bit)"
        elif length == 128:
            return "sha-512 or whirlpool (raw, 512-bit)"
        else:
            return f"Unknown hex hash ({length} chars)"

    return "Unknown hash type"

def get_hash_info(hash_type):
    return hash_info.get(hash_type.lower(), {"hashcat": "-", "john": "-"})

@app.route("/", methods=["GET", "POST"])
def index():
    if "history" not in session:
        session["history"] = []

    if request.method == "POST":
        if request.form.get("clear_history"):
            session["history"] = []

        elif request.form.get("delete_hash"):
            delete_hash = request.form.get("delete_hash")
            session["history"] = [r for r in session["history"] if r["hash"] != delete_hash]

        else:
            user_input = request.form.get("hash_input", "")
            hashes = [h.strip() for h in user_input.splitlines() if h.strip()]
            for h in hashes:
                hash_type = identify_hash(h)
                info = get_hash_info(hash_type)
                session["history"].append({
                    "hash": h,
                    "type": hash_type,
                    "hashcat": info["hashcat"],
                    "john": info["john"]
                })

        session.modified = True

    return render_template("index.html", results=session.get("history", []))

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port, debug=False)
