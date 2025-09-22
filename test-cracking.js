const { crackHash, generateHash } = require('./netlify/functions/hash-cracker');

// Test cases with known passwords
const testCases = [
    // Easy dictionary passwords
    { password: 'hello', algorithm: 'md5' },
    { password: 'test', algorithm: 'md5' },
    { password: 'password', algorithm: 'sha1' },
    { password: 'admin', algorithm: 'sha256' },
    { password: 'hello123', algorithm: 'md5' },
    
    // NTLM tests
    { password: 'hello', algorithm: 'ntlm' },
    { password: '', algorithm: 'ntlm' }, // empty password
    
    // Brute force tests (short passwords)
    { password: 'a', algorithm: 'md5' },
    { password: '123', algorithm: 'sha1' },
];

async function testCracking() {
    console.log("🔓 Testing Hash Cracking Functionality\n");
    console.log("=" .repeat(80));

    let passed = 0;
    let failed = 0;

    for (const testCase of testCases) {
        const hash = generateHash(testCase.password, testCase.algorithm);
        if (!hash) {
            console.log(`❌ Failed to generate ${testCase.algorithm} hash for '${testCase.password}'`);
            failed++;
            continue;
        }

        const hashType = `${testCase.algorithm} (raw, ${testCase.algorithm === 'md5' ? '128' : testCase.algorithm === 'sha1' ? '160' : testCase.algorithm === 'sha256' ? '256' : testCase.algorithm === 'ntlm' ? 'nt hash' : 'unknown'}-bit)`;
        
        console.log(`\nTesting: ${testCase.password === '' ? '<empty>' : testCase.password} (${testCase.algorithm})`);
        console.log(`Hash: ${hash}`);
        
        try {
            const result = await crackHash(hash, hashType);
            
            if (result.cracked && result.password === testCase.password) {
                console.log(`✅ PASS - Cracked using ${result.method} in ${result.timeElapsed}ms`);
                passed++;
            } else if (result.cracked) {
                console.log(`❌ FAIL - Cracked but wrong password: '${result.password}' (expected '${testCase.password}')`);
                failed++;
            } else {
                console.log(`❌ FAIL - Could not crack: ${result.message}`);
                failed++;
            }
        } catch (error) {
            console.log(`❌ ERROR - ${error.message}`);
            failed++;
        }
        
        console.log("-".repeat(80));
    }

    console.log(`\n📊 Cracking Test Results: ${passed} passed, ${failed} failed`);

    if (failed === 0) {
        console.log("🎉 All cracking tests passed!");
    } else {
        console.log("⚠️  Some cracking tests failed.");
    }
}

// Run the tests
testCracking().catch(console.error);
