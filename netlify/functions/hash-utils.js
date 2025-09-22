// Hash identification logic
function identifyHash(hashStr) {
    hashStr = hashStr.trim();
    const length = hashStr.length;
    const hashLower = hashStr.toLowerCase();

    // Check for specific hash formats first (most specific to least specific)
    
    // Crypt-style hashes (Unix/Linux password hashes)
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
    if (hashLower.startsWith("$argon2")) {
        return "argon2 (modern password hash)";
    }

    // WordPress and other CMS hashes
    if (hashLower.startsWith("$p$") || hashLower.startsWith("$h$")) {
        return "phpass (wordpress/phpbb)";
    }

    // Base64-encoded hashes (common in some systems)
    if (/^[A-Za-z0-9+\/]+=*$/.test(hashStr)) {
        if (length === 24) {
            return "md5 (base64)";
        } else if (length === 28) {
            return "sha-1 (base64)";
        } else if (length === 44) {
            return "sha-256 (base64)";
        } else if (length === 88) {
            return "sha-512 (base64)";
        }
    }

    // LM Hash (always uppercase, 32 chars, specific pattern)
    if (length === 32 && /^[0-9A-F]+$/.test(hashStr) && 
        (hashStr.endsWith("AAD3B435B51404EE") || hashStr.startsWith("AAD3B435B51404EE"))) {
        return "lm hash (LANMAN)";
    }

    // MySQL hashes
    if (hashStr.startsWith("*") && length === 41 && /^\*[0-9A-Fa-f]{40}$/.test(hashStr)) {
        return "mysql 4.1+ (sha-1 based)";
    }

    // NTLM specific patterns (common in Windows environments)
    if (length === 32 && /^[0-9a-fA-F]+$/.test(hashStr)) {
        // Check for common NTLM patterns or if it's likely NTLM
        // NTLM hashes often have certain characteristics
        const hasUpperCase = /[A-F]/.test(hashStr);
        const hasLowerCase = /[a-f]/.test(hashStr);
        
        // If it's all uppercase or has mixed case in a Windows-like pattern, likely NTLM
        if (hashStr === hashStr.toUpperCase() || (hasUpperCase && hasLowerCase)) {
            return "ntlm (nt hash)";
        }
        // Otherwise, default to MD5 as it's more common
        return "md5 (raw, 128-bit)";
    }

    // Hex-only hashes (raw format)
    if (/^[0-9a-fA-F]+$/.test(hashStr)) {
        switch (length) {
            case 16:
                return "md2 (raw, 128-bit)";
            case 32:
                // Most common 32-char hashes (in order of likelihood)
                return "md5 (raw, 128-bit)"; // Default to MD5 as it's most common
            case 40:
                return "sha-1 (raw, 160-bit)";
            case 56:
                return "sha-224 (raw, 224-bit)";
            case 64:
                return "sha-256 (raw, 256-bit)";
            case 96:
                return "sha-384 (raw, 384-bit)";
            case 128:
                return "sha-512 (raw, 512-bit)";
            case 136:
                return "sha-512 salted";
            default:
                return `unknown hex hash (${length} characters)`;
        }
    }

    // Check for salted hashes (hash:salt format)
    if (hashStr.includes(':')) {
        const parts = hashStr.split(':');
        if (parts.length === 2) {
            const hashPart = parts[0];
            const saltPart = parts[1];
            
            if (/^[0-9a-fA-F]+$/.test(hashPart)) {
                switch (hashPart.length) {
                    case 32:
                        return "md5 salted (hash:salt)";
                    case 40:
                        return "sha-1 salted (hash:salt)";
                    case 64:
                        return "sha-256 salted (hash:salt)";
                    case 128:
                        return "sha-512 salted (hash:salt)";
                }
            }
        }
    }

    // Check for other common formats
    if (length === 13 && /^[a-zA-Z0-9\.\/]+$/.test(hashStr)) {
        return "des-crypt (traditional unix)";
    }

    return "unknown hash type";
}

// Hash information database
const hashInfo = {
    // Raw hash formats
    "md2 (raw, 128-bit)": { "hashcat": "-", "john": "raw-md2" },
    "md5 (raw, 128-bit)": { "hashcat": "0", "john": "raw-md5" },
    "md4 (raw, 128-bit)": { "hashcat": "900", "john": "raw-md4" },
    "sha-1 (raw, 160-bit)": { "hashcat": "100", "john": "raw-sha1" },
    "sha-224 (raw, 224-bit)": { "hashcat": "6110", "john": "raw-sha224" },
    "sha-256 (raw, 256-bit)": { "hashcat": "1400", "john": "raw-sha256" },
    "sha-384 (raw, 384-bit)": { "hashcat": "10800", "john": "raw-sha384" },
    "sha-512 (raw, 512-bit)": { "hashcat": "1700", "john": "raw-sha512" },
    "whirlpool (raw, 512-bit)": { "hashcat": "6100", "john": "raw-whirlpool" },
    
    // Base64 encoded hashes
    "md5 (base64)": { "hashcat": "0", "john": "raw-md5" },
    "sha-1 (base64)": { "hashcat": "100", "john": "raw-sha1" },
    "sha-256 (base64)": { "hashcat": "1400", "john": "raw-sha256" },
    "sha-512 (base64)": { "hashcat": "1700", "john": "raw-sha512" },
    
    // Salted hashes
    "md5 salted (hash:salt)": { "hashcat": "10", "john": "raw-md5-generic" },
    "sha-1 salted (hash:salt)": { "hashcat": "110", "john": "raw-sha1-generic" },
    "sha-256 salted (hash:salt)": { "hashcat": "1410", "john": "raw-sha256-generic" },
    "sha-512 salted (hash:salt)": { "hashcat": "1710", "john": "raw-sha512-generic" },
    "sha-512 salted": { "hashcat": "1710", "john": "raw-sha512-generic" },
    
    // Windows hashes
    "ntlm (nt hash)": { "hashcat": "1000", "john": "nt" },
    "lm hash (LANMAN)": { "hashcat": "3000", "john": "lm" },
    "domain cached creds (MS cache)": { "hashcat": "1100", "john": "mscash" },
    
    // Unix/Linux crypt hashes
    "des-crypt (traditional unix)": { "hashcat": "1500", "john": "descrypt" },
    "md5-crypt (unix md5)": { "hashcat": "500", "john": "md5crypt" },
    "sha-256-crypt (unix sha-256)": { "hashcat": "7400", "john": "sha256crypt" },
    "sha-512-crypt (unix sha-512)": { "hashcat": "1800", "john": "sha512crypt" },
    "bcrypt (blowfish-based password hash)": { "hashcat": "3200", "john": "bcrypt" },
    "yescrypt (modern password hash)": { "hashcat": "-", "john": "yescrypt" },
    "argon2 (modern password hash)": { "hashcat": "-", "john": "argon2" },
    
    // Application-specific hashes
    "mysql 4.1+ (sha-1 based)": { "hashcat": "300", "john": "mysql-sha1" },
    "phpass (wordpress/phpbb)": { "hashcat": "400", "john": "phpass" },
    "cisco ios scrypt": { "hashcat": "-", "john": "cisco-ios-scrypt" },
    
    // Complex hash formats
    "md5(md5())": { "hashcat": "60", "john": "-" },
    "md5(sha1())": { "hashcat": "61", "john": "-" },
    
    // Unknown/fallback
    "unknown hash type": { "hashcat": "-", "john": "-" }
};

module.exports = {
    identifyHash,
    hashInfo
};
