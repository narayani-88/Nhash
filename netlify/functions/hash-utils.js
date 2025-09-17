// Hash identification logic
function identifyHash(hashStr) {
    hashStr = hashStr.trim();
    const length = hashStr.length;
    const hashLower = hashStr.toLowerCase();

    // Crypt-style hashes
    if (hashLower.startsWith("$2a$") || hashLower.startsWith("$2b$") || hashLower.startsWith("$2y$")) {
        return "bcrypt (blowfish-based password hash)";
    }
    if (hashLower.startsWith("$1$")) {
        return "md5-crypt (unix md5)";
    }
    if (hashLower.startsWith("$5$")) {
        return "sha-256-crypt (unix sha-256)";
    }
    if (hashLower.startsWith("$6$")) {
        return "sha-512-crypt (unix sha-512)";
    }
    if (hashLower.startsWith("$y$")) {
        return "yescrypt (modern password hash)";
    }
    if (hashLower.startsWith("$9$")) {
        return "cisco ios scrypt";
    }

    // Hex-only hashes
    if (/^[0-9a-fA-F]+$/.test(hashStr)) {
        if (length === 32) {
            return "ntlm (nt hash)";
        } else if (length === 40) {
            return "sha-1 (raw, 160-bit)";
        } else if (length === 56) {
            return "sha-224 (raw, 224-bit)";
        } else if (length === 64) {
            return "sha-256 (raw, 256-bit)";
        } else if (length === 96) {
            return "sha-384 (raw, 384-bit)";
        } else if (length === 128) {
            return "sha-512 or whirlpool (raw, 512-bit)";
        } else {
            return `Unknown hex hash (${length} chars)`;
        }
    }

    return "Unknown hash type";
}

// Hash information database
const hashInfo = {
    "md5 (raw, 128-bit)": { "hashcat": "0", "john": "raw-md5" },
    "md4 (raw, 128-bit)": { "hashcat": "900", "john": "raw-md4" },
    "md5(md5())": { "hashcat": "60", "john": "-" },
    "md5(sha1())": { "hashcat": "61", "john": "-" },
    "sha-1 (raw, 160-bit)": { "hashcat": "100", "john": "raw-sha1" },
    "sha-224 (raw, 224-bit)": { "hashcat": "6110", "john": "raw-sha224" },
    "sha-256 (raw, 256-bit)": { "hashcat": "1400", "john": "raw-sha256" },
    "sha-384 (raw, 384-bit)": { "hashcat": "10800", "john": "raw-sha384" },
    "sha-512 (raw, 512-bit)": { "hashcat": "1700", "john": "raw-sha512" },
    "whirlpool (raw, 512-bit)": { "hashcat": "6100", "john": "raw-whirlpool" },
    "ntlm (nt hash)": { "hashcat": "1000", "john": "nt" },
    "md5-crypt (unix md5)": { "hashcat": "500", "john": "md5crypt" },
    "sha-256-crypt (unix sha-256)": { "hashcat": "7400", "john": "sha256crypt" },
    "sha-512-crypt (unix sha-512)": { "hashcat": "1800", "john": "sha512crypt" },
    "bcrypt (blowfish-based password hash)": { "hashcat": "3200", "john": "bcrypt" },
    "yescrypt (modern password hash)": { "hashcat": "-", "john": "yescrypt" },
    "cisco ios scrypt": { "hashcat": "-", "john": "cisco-ios-scrypt" },
    "lm hash (LANMAN)": { "hashcat": "3000", "john": "lm" },
    "domain cached creds (MS cache)": { "hashcat": "1100", "john": "mscash" }
};

module.exports = {
    identifyHash,
    hashInfo
};
