const { identifyHash } = require('./netlify/functions/hash-utils');

// Test the exact SHA-256 hash you provided
const sha256Hash = '5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8';

console.log('Testing SHA-256 hash identification:');
console.log('Hash:', sha256Hash);
console.log('Length:', sha256Hash.length);
console.log('Is hex?', /^[0-9a-fA-F]+$/.test(sha256Hash));

const result = identifyHash(sha256Hash);
console.log('Identified as:', result);

// Also test the MD5 hash for comparison
const md5Hash = '5f4dcc3b5aa765d61d8327deb882cf99';
console.log('\nTesting MD5 hash for comparison:');
console.log('Hash:', md5Hash);
console.log('Length:', md5Hash.length);
console.log('Identified as:', identifyHash(md5Hash));
