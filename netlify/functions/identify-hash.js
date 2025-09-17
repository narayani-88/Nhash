const hashInfo = {
    // MD5
    "md5": { "hashcat": "0", "john": "raw-md5" },
    "md5(md5($pass))": { "hashcat": "2600", "john": "md5(md5($pass))" },
    "md5($pass.$salt)": { "hashcat": "10", "john": "dynamic_1034" },
    "md5($salt.$pass)": { "hashcat": "20", "john": "dynamic_20" },
    "md5(utf16le($pass))": { "hashcat": "30", "john": "dynamic_30" },
    "md5($salt.utf16le($pass))": { "hashcat": "40", "john": "dynamic_40" },
    "md5($salt.$pass.$salt)": { "hashcat": "50", "john": "dynamic_50" },
    "md5($salt.md5($pass))": { "hashcat": "60", "john": "dynamic_60" },
    "md5(md5($salt).$pass)": { "hashcat": "70", "john": "dynamic_70" },
    "md5($salt.md5($salt.$pass))": { "hashcat": "80", "john": "dynamic_80" },
    "md5($salt.md5($pass.$salt))": { "hashcat": "90", "john": "dynamic_90" },
    "md5($username.0.$pass)": { "hashcat": "100", "john": "dynamic_100" },
    "md5(strtoupper(md5($pass)))": { "hashcat": "110", "john": "dynamic_110" },

    // SHA-1
    "sha1": { "hashcat": "100", "john": "raw-sha1" },
    "sha1($pass.$salt)": { "hashcat": "110", "john": "dynamic_110" },
    "sha1($salt.$pass)": { "hashcat": "120", "john": "dynamic_120" },
    "sha1(utf16le($pass))": { "hashcat": "130", "john": "dynamic_130" },
    "sha1($salt.utf16le($pass))": { "hashcat": "140", "john": "dynamic_140" },
    "sha1($salt.$pass.$salt)": { "hashcat": "150", "john": "dynamic_150" },
    "sha1($salt.sha1($pass))": { "hashcat": "160", "john": "dynamic_160" },
    "sha1($salt.sha1($salt.$pass))": { "hashcat": "170", "john": "dynamic_170" },
    "sha1($salt.sha1($pass.$salt))": { "hashcat": "180", "john": "dynamic_180" },
    "sha1($username.$pass)": { "hashcat": "190", "john": "dynamic_190" },
    "sha1($username.$pass.$salt)": { "hashcat": "200", "john": "dynamic_200" },

    // SHA-256
    "sha256": { "hashcat": "1400", "john": "raw-sha256" },
    "sha256($pass.$salt)": { "hashcat": "1410", "john": "dynamic_1410" },
    "sha256($salt.$pass)": { "hashcat": "1420", "john": "dynamic_1420" },
    "sha256(utf16le($pass))": { "hashcat": "1430", "john": "dynamic_1430" },
    "sha256($salt.utf16le($pass))": { "hashcat": "1440", "john": "dynamic_1440" },
    "sha256($salt.$pass.$salt)": { "hashcat": "1450", "john": "dynamic_1450" },
    "sha256($salt.sha256($pass))": { "hashcat": "1460", "john": "dynamic_1460" },
    "sha256($salt.sha256($salt.$pass))": { "hashcat": "1470", "john": "dynamic_1470" },
    "sha256($salt.sha256($pass.$salt))": { "hashcat": "1480", "john": "dynamic_1480" },

    // SHA-512
    "sha512": { "hashcat": "1700", "john": "raw-sha512" },
    "sha512($pass.$salt)": { "hashcat": "1710", "john": "dynamic_1710" },
    "sha512($salt.$pass)": { "hashcat": "1720", "john": "dynamic_1720" },
    "sha512(utf16le($pass))": { "hashcat": "1730", "john": "dynamic_1730" },
    "sha512($salt.utf16le($pass))": { "hashcat": "1740", "john": "dynamic_1740" },
    "sha512($salt.$pass.$salt)": { "hashcat": "1750", "john": "dynamic_1750" },
    "sha512($salt.sha512($pass))": { "hashcat": "1760", "john": "dynamic_1760" },
    "sha512($salt.sha512($salt.$pass))": { "hashcat": "1770", "john": "dynamic_1770" },
    "sha512($salt.sha512($pass.$salt))": { "hashcat": "1780", "john": "dynamic_1780" },

    // bcrypt
    "bcrypt": { "hashcat": "3200", "john": "bcrypt" },
    "bcrypt(md5($pass))": { "hashcat": "3210", "john": "bcrypt-md5" },
    "bcrypt(sha1($pass))": { "hashcat": "3220", "john": "bcrypt-sha1" },
    "bcrypt(sha256($pass))": { "hashcat": "3230", "john": "bcrypt-sha256" },
    "bcrypt(sha512($pass))": { "hashcat": "3240", "john": "bcrypt-sha512" },

    // NTLM
    "ntlm": { "hashcat": "1000", "john": "nt" },
    "ntlmv1": { "hashcat": "5500", "john": "netntlmv1" },
    "ntlmv2": { "hashcat": "5600", "john": "netntlmv2" },

    // MySQL
    "mysql": { "hashcat": "200", "john": "mysql" },
    "mysql5": { "hashcat": "300", "john": "mysql-sha1" },
    "mysql4.1+": { "hashcat": "400", "john": "mysql-sha1" },

    // PostgreSQL
    "postgres": { "hashcat": "1110", "john": "postgres" },

    // MS SQL
    "mssql": { "hashcat": "131", "john": "mssql" },
    "mssql05": { "hashcat": "132", "john": "mssql05" },
    "mssql12": { "hashcat": "1731", "john": "mssql12" },

    // Oracle
    "oracle7": { "hashcat": "3100", "john": "oracle" },
    "oracle11": { "hashcat": "112", "john": "oracle11" },
    "oracle12c": { "hashcat": "12300", "john": "oracle12c" },

    // Bitcoin
    "bitcoin": { "hashcat": "11300", "john": "bitcoin" },
    "ethereum": { "hashcat": "15700", "john": "ethereum" },

    // Other common hashes
    "crc32": { "hashcat": "11500", "john": "crc32" },
    "salted_sha1": { "hashcat": "110", "john": "salted-sha1" },
    "salted_sha256": { "hashcat": "1410", "john": "salted-sha256" },
    "salted_sha512": { "hashcat": "1710", "john": "salted-sha512" }
};

exports.handler = async (event, context) => {
    if (event.httpMethod !== 'POST') {
        return { statusCode: 405, body: 'Method Not Allowed' };
    }

    try {
        const { hash } = JSON.parse(event.body);
        if (!hash) {
            throw new Error('No hash provided');
        }

        const result = identifyHash(hash);
        
        return {
            statusCode: 200,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Methods': 'POST, OPTIONS'
            },
            body: JSON.stringify({
                type: result,
                hashcat: hashInfo[result]?.hashcat || 'N/A',
                john: hashInfo[result]?.john || 'N/A',
                hash: hash
            })
        };
    } catch (error) {
        return {
            statusCode: 400,
            headers: {
                'Access-Control-Allow-Origin': '*',
                'Access-Control-Allow-Headers': 'Content-Type',
                'Access-Control-Allow-Methods': 'POST, OPTIONS'
            },
            body: JSON.stringify({ 
                error: error.message || 'Failed to identify hash',
                type: 'unknown'
            })
        };
    }
};

function identifyHash(hash) {
    if (!hash || typeof hash !== 'string') {
        return 'unknown';
    }

    const hashLower = hash.toLowerCase();
    const length = hash.length;

    // MD5 (32 chars)
    if (length === 32 && /^[a-f0-9]{32}$/i.test(hash)) {
        return 'md5';
    }
    
    // SHA-1 (40 chars)
    if (length === 40 && /^[a-f0-9]{40}$/i.test(hash)) {
        return 'sha1';
    }
    
    // SHA-256 (64 chars)
    if (length === 64 && /^[a-f0-9]{64}$/i.test(hash)) {
        return 'sha256';
    }
    
    // SHA-512 (128 chars)
    if (length === 128 && /^[a-f0-9]{128}$/i.test(hash)) {
        return 'sha512';
    }
    
    // MySQL < 4.1 (16 chars)
    if (length === 16 && /^[a-f0-9]{16}$/i.test(hash)) {
        return 'mysql';
    }
    
    // MySQL 4.1+ (40 chars, starts with an asterisk)
    if (length === 41 && hash[0] === '*' && /^\*[a-f0-9]{40}$/i.test(hash)) {
        return 'mysql4.1+';
    }
    
    // NTLM (32 chars, uppercase)
    if (length === 32 && /^[A-F0-9]{32}$/i.test(hash)) {
        return 'ntlm';
    }
    
    // bcrypt (starts with $2a$, $2b$, $2y$)
    if ((hashLower.startsWith('$2a$') || 
         hashLower.startsWith('$2b$') || 
         hashLower.startsWith('$2y$')) && 
        hash.length >= 59) {
        return 'bcrypt';
    }
    
    // If no specific pattern matches, try to guess based on length
    if (length === 32) return 'md5';
    if (length === 40) return 'sha1';
    if (length === 64) return 'sha256';
    if (length === 128) return 'sha512';
    
    return 'unknown';
}
