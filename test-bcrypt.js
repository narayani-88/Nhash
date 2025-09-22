// Test bcrypt cracking functionality
let bcrypt;
try {
    bcrypt = require('bcrypt');
} catch (error) {
    console.log('❌ bcrypt not available, install with: npm install bcrypt');
    process.exit(1);
}

const { bcryptAttack } = require('./netlify/functions/hash-cracker');

async function testBcryptCracking() {
    console.log("🔓 Testing Bcrypt Cracking Functionality\n");
    console.log("=" .repeat(80));

    // Create test bcrypt hashes with known passwords
    const testPasswords = ['password', 'admin', 'hello', '123456'];
    
    for (const password of testPasswords) {
        console.log(`\nTesting password: "${password}"`);
        
        try {
            // Generate bcrypt hash (cost 10 for faster testing)
            const hash = await bcrypt.hash(password, 10);
            console.log(`Generated hash: ${hash}`);
            
            // Try to crack it
            console.log('Attempting to crack...');
            const startTime = Date.now();
            
            const result = await bcryptAttack(hash, 10, 5000); // 10 attempts, 5 second timeout
            
            console.log(`Result: ${result.cracked ? '✅ CRACKED' : '❌ NOT CRACKED'}`);
            if (result.cracked) {
                console.log(`Password: "${result.password}"`);
                console.log(`Method: ${result.method}`);
            } else {
                console.log(`Reason: ${result.message}`);
            }
            console.log(`Time: ${result.timeElapsed}ms`);
            
        } catch (error) {
            console.log(`❌ Error: ${error.message}`);
        }
        
        console.log("-".repeat(80));
    }
}

// Run the test
testBcryptCracking().catch(console.error);
