const crypto = require('crypto');

// Common password dictionary
const commonPasswords = [
    'password', '123456', '123456789', 'qwerty', 'abc123', 'password123',
    'admin', 'letmein', 'welcome', 'monkey', '1234567890', 'dragon',
    'sunshine', 'princess', 'football', 'charlie', 'aa123456', 'donald',
    'password1', 'qwerty123', 'hello', 'login', 'master', 'solo',
    'hello123', 'freedom', 'whatever', 'qazwsx', 'trustno1', 'batman',
    'zaq1zaq1', 'qwertyuiop', 'superman', 'naruto', 'shadow', 'michael',
    'mustang', 'mercedes', 'jordan23', 'harley', 'robert', 'matthew',
    'daniel', 'andrew', 'joshua', 'anthony', 'william', 'david',
    'richard', 'charles', 'thomas', 'christopher', 'john', 'james',
    'test', 'guest', 'info', 'adm', 'mysql', 'user', 'administrator',
    'oracle', 'ftp', 'pi', 'puppet', 'ansible', 'ec2-user', 'vagrant',
    'azureuser', 'demo', 'test123', 'root', 'toor', 'pass', 'secret'
];

// Generate hash using different algorithms
function generateHash(password, algorithm) {
    switch (algorithm) {
        case 'md5':
            return crypto.createHash('md5').update(password).digest('hex');
        case 'sha1':
            return crypto.createHash('sha1').update(password).digest('hex');
        case 'sha256':
            return crypto.createHash('sha256').update(password).digest('hex');
        case 'sha512':
            return crypto.createHash('sha512').update(password).digest('hex');
        case 'ntlm':
            // NTLM is MD4 of UTF-16LE encoded password
            const utf16Password = Buffer.from(password, 'utf8').toString('utf16le');
            return crypto.createHash('md4').update(utf16Password, 'utf16le').digest('hex');
        default:
            return null;
    }
}

// Dictionary attack
function dictionaryAttack(targetHash, hashType) {
    const algorithm = getAlgorithmFromType(hashType);
    if (!algorithm) return null;

    // Check common passwords
    for (const password of commonPasswords) {
        const hash = generateHash(password, algorithm);
        if (hash && hash.toLowerCase() === targetHash.toLowerCase()) {
            return {
                method: 'dictionary',
                password: password,
                time: 'instant'
            };
        }
    }

    // Check common variations
    const variations = generateVariations(commonPasswords.slice(0, 20)); // Limit to prevent timeout
    for (const password of variations) {
        const hash = generateHash(password, algorithm);
        if (hash && hash.toLowerCase() === targetHash.toLowerCase()) {
            return {
                method: 'dictionary_variation',
                password: password,
                time: 'fast'
            };
        }
    }

    return null;
}

// Generate password variations
function generateVariations(passwords) {
    const variations = [];
    
    for (const password of passwords) {
        // Add numbers at the end
        for (let i = 0; i <= 999; i++) {
            if (variations.length > 1000) break; // Limit variations
            variations.push(password + i);
        }
        
        // Capitalize first letter
        variations.push(password.charAt(0).toUpperCase() + password.slice(1));
        
        // All uppercase
        variations.push(password.toUpperCase());
        
        // Add common suffixes
        const suffixes = ['!', '@', '#', '$', '123', '1', '2', '3', '21', '01', '2023', '2024'];
        for (const suffix of suffixes) {
            variations.push(password + suffix);
            variations.push(password.charAt(0).toUpperCase() + password.slice(1) + suffix);
        }
    }
    
    return [...new Set(variations)]; // Remove duplicates
}

// Brute force attack (limited scope for web environment)
function bruteForceAttack(targetHash, hashType, maxLength = 4) {
    const algorithm = getAlgorithmFromType(hashType);
    if (!algorithm) return null;

    const charset = 'abcdefghijklmnopqrstuvwxyz0123456789';
    
    // Try single characters first
    for (let length = 1; length <= Math.min(maxLength, 4); length++) {
        const result = bruteForceLength(targetHash, algorithm, charset, length);
        if (result) {
            return {
                method: 'brute_force',
                password: result,
                time: length <= 2 ? 'fast' : 'slow'
            };
        }
    }
    
    return null;
}

// Brute force for specific length
function bruteForceLength(targetHash, algorithm, charset, length) {
    function generateCombinations(chars, len, current = '') {
        if (current.length === len) {
            const hash = generateHash(current, algorithm);
            if (hash && hash.toLowerCase() === targetHash.toLowerCase()) {
                return current;
            }
            return null;
        }
        
        for (let i = 0; i < chars.length; i++) {
            const result = generateCombinations(chars, len, current + chars[i]);
            if (result) return result;
        }
        return null;
    }
    
    return generateCombinations(charset, length);
}

// Online hash lookup (simulated - in real implementation, you'd call actual APIs)
async function onlineLookup(targetHash, hashType) {
    // Simulate some known cracked hashes
    const knownHashes = {
        // MD5
        '5d41402abc4b2a76b9719d911017c592': 'hello',
        '098f6bcd4621d373cade4e832627b4f6': 'test',
        '25d55ad283aa400af464c76d713c07ad': 'hello world',
        'e99a18c428cb38d5f260853678922e03': 'abc123',
        '25f9e794323b453885f5181f1b624d0b': 'hello123',
        
        // SHA1
        'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d': 'hello',
        'da39a3ee5e6b4b0d3255bfef95601890afd80709': '', // empty string
        '356a192b7913b04c54574d18c28d46e6395428ab': '1',
        'da4b9237bacccdf19c0760cab7aec4a8359010b0': '2',
        
        // SHA256
        '2cf24dba4f21d4288094c25e2d560a6c7b3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c': 'hello',
        'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855': '', // empty string
        
        // NTLM
        'b4b9b02e6f09a9bd760f388b67351e2b': 'hello',
        '31d6cfe0d16ae931b73c59d7e0c089c0': '', // empty string
    };
    
    const hash = targetHash.toLowerCase();
    if (knownHashes[hash]) {
        return {
            method: 'online_database',
            password: knownHashes[hash],
            time: 'instant'
        };
    }
    
    return null;
}

// Get algorithm name from hash type
function getAlgorithmFromType(hashType) {
    if (hashType.includes('md5')) return 'md5';
    if (hashType.includes('sha-1')) return 'sha1';
    if (hashType.includes('sha-256')) return 'sha256';
    if (hashType.includes('sha-512')) return 'sha512';
    if (hashType.includes('ntlm')) return 'ntlm';
    return null;
}

// Main cracking function
async function crackHash(targetHash, hashType) {
    const startTime = Date.now();
    
    // Try online lookup first (fastest)
    const onlineResult = await onlineLookup(targetHash, hashType);
    if (onlineResult) {
        return {
            ...onlineResult,
            cracked: true,
            timeElapsed: Date.now() - startTime
        };
    }
    
    // Try dictionary attack
    const dictResult = dictionaryAttack(targetHash, hashType);
    if (dictResult) {
        return {
            ...dictResult,
            cracked: true,
            timeElapsed: Date.now() - startTime
        };
    }
    
    // Try brute force for short passwords only
    if (targetHash.length <= 64) { // Only for shorter hashes
        const bruteResult = bruteForceAttack(targetHash, hashType, 3);
        if (bruteResult) {
            return {
                ...bruteResult,
                cracked: true,
                timeElapsed: Date.now() - startTime
            };
        }
    }
    
    return {
        cracked: false,
        method: 'none',
        message: 'Hash could not be cracked with available methods',
        timeElapsed: Date.now() - startTime
    };
}

module.exports = {
    crackHash,
    generateHash,
    dictionaryAttack,
    bruteForceAttack,
    onlineLookup
};
