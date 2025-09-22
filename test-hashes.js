const { identifyHash, hashInfo } = require('./netlify/functions/hash-utils');

// Test cases with known hash types
const testCases = [
    // MD5 hashes (32 chars)
    { hash: "5d41402abc4b2a76b9719d911017c592", expected: "md5 (raw, 128-bit)" },
    { hash: "098f6bcd4621d373cade4e832627b4f6", expected: "md5 (raw, 128-bit)" },
    
    // SHA-1 hashes (40 chars)
    { hash: "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d", expected: "sha-1 (raw, 160-bit)" },
    { hash: "da39a3ee5e6b4b0d3255bfef95601890afd80709", expected: "sha-1 (raw, 160-bit)" },
    
    // SHA-256 hashes (64 chars)
    { hash: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", expected: "sha-256 (raw, 256-bit)" },
    { hash: "2cf24dba4f21d4288094c25e2d560a6c7b3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c", expected: "sha-256 (raw, 256-bit)" },
    
    // NTLM hashes (32 chars, uppercase)
    { hash: "B4B9B02E6F09A9BD760F388B67351E2B", expected: "ntlm (nt hash)" },
    { hash: "AAD3B435B51404EEAAD3B435B51404EE", expected: "lm hash (LANMAN)" },
    
    // Unix crypt hashes
    { hash: "$1$salt$qJH7.N4xYta3aEG/dfqo/0", expected: "md5-crypt (unix md5)" },
    { hash: "$6$salt$IxDD3jeSOb5eB1CX5LBsqZFVkJdido3OUILO5Ifz5iwMuTS4XMS130MTSuDDl3aCI6WouIL9AjRbLCelDCy.g.", expected: "sha-512-crypt (unix sha-512)" },
    
    // bcrypt hashes
    { hash: "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy", expected: "bcrypt (blowfish-based password hash)" },
    
    // MySQL hashes
    { hash: "*23AE809DDACAF96AF0FD78ED04B6A265E05AA257", expected: "mysql 4.1+ (sha-1 based)" },
    
    // Salted hashes
    { hash: "5d41402abc4b2a76b9719d911017c592:salt123", expected: "md5 salted (hash:salt)" },
    { hash: "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d:mysalt", expected: "sha-1 salted (hash:salt)" },
];

console.log("🔍 Testing Hash Identification Logic\n");
console.log("=" .repeat(80));

let passed = 0;
let failed = 0;

testCases.forEach((testCase, index) => {
    const result = identifyHash(testCase.hash);
    const info = hashInfo[result] || { hashcat: '-', john: '-' };
    
    const status = result === testCase.expected ? "✅ PASS" : "❌ FAIL";
    
    if (result === testCase.expected) {
        passed++;
    } else {
        failed++;
    }
    
    console.log(`Test ${index + 1}: ${status}`);
    console.log(`  Hash: ${testCase.hash}`);
    console.log(`  Expected: ${testCase.expected}`);
    console.log(`  Got: ${result}`);
    console.log(`  Hashcat: ${info.hashcat} | John: ${info.john}`);
    console.log("-".repeat(80));
});

console.log(`\n📊 Test Results: ${passed} passed, ${failed} failed`);

if (failed === 0) {
    console.log("🎉 All tests passed! Hash identification is working correctly.");
} else {
    console.log("⚠️  Some tests failed. Please review the logic.");
}
