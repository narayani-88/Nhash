from flask import Flask, render_template, request, session
import re

app = Flask(__name__)
app.secret_key = "supersecretkey"

# Extended hash info
hash_info = {
    # Raw Hashes
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
    "ripemd-160": {"hashcat": "110", "john": "raw-ripemd"},
    "ntlm (nt hash)": {"hashcat": "1000", "john": "nt"},

    # Unix Crypt-style hashes
    "md5-crypt (unix md5)": {"hashcat": "500", "john": "md5crypt"},
    "sha-256-crypt (unix sha-256)": {"hashcat": "7400", "john": "sha256crypt"},
    "sha-512-crypt (unix sha-512)": {"hashcat": "1800", "john": "sha512crypt"},
    "bcrypt (blowfish-based password hash)": {"hashcat": "3200", "john": "bcrypt"},
    "yescrypt (modern password hash)": {"hashcat": "-", "john": "yescrypt"},
    "cisco ios scrypt": {"hashcat": "-", "john": "cisco-ios-scrypt"},
    "mysql323": {"hashcat": "200", "john": "mysql"},
    "mysql41": {"hashcat": "300", "john": "mysql-sha1"},
    "oracle 10g": {"hashcat": "112", "john": "oracle10g"},
    "oracle 11g": {"hashcat": "113", "john": "oracle11g"},
    "mssql (2000)": {"hashcat": "131", "john": "mssql"},
    "mssql (2012)": {"hashcat": "142", "john": "mssql12"},
    "sap-netweaver": {"hashcat": "2100", "john": "sap"},
    "juniper netscreen/ssg (sha1)": {"hashcat": "121", "john": "netscreen"},
    "sip digest authentication": {"hashcat": "400", "john": "sip"},
    "des (unix)": {"hashcat": "1500", "john": "des"},
    "lm hash (LANMAN)": {"hashcat": "3000", "john": "lm"},
    "domain cached creds (MS cache)": {"hashcat": "1100", "john": "mscash"},
    "android backup (pbkdf2-sha1)": {"hashcat": "116", "john": "android-backup"},
    "zip (PKZIP)": {"hashcat": "17200", "john": "zip"},
    "rar3-hp": {"hashcat": "12500", "john": "rar3"},
    "rar5": {"hashcat": "13000", "john": "rar5"},
    "7z": {"hashcat": "11600", "john": "7z"},
    "office (2007-2010)": {"hashcat": "9400", "john": "office"},
    "office (2013)": {"hashcat": "9500", "john": "office2013"},
    "pdf 1.4 - 1.6 (Acrobat 5 - 8)": {"hashcat": "10500", "john": "pdf"},
    "pdf 1.7 Level 8 (Acrobat 9)": {"hashcat": "10600", "john": "pdf"},
    "iphone backup (iOS 10.0+)": {"hashcat": "12300", "john": "iphone-backup"},
    "wpapsk (WPA/WPA2 PSK)": {"hashcat": "2500", "john": "wpapsk"},
    "btcwallet (Bitcoin)": {"hashcat": "11300", "john": "btcwallet"},
    "ethereum (UTC / JSON)": {"hashcat": "15700", "john": "ethereum"},
    "ssh private key (OpenSSH/PEM)": {"hashcat": "16200", "john": "ssh-opencl"},
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
    app.run(debug=True)
