const { hashInfo, identifyHash } = require('./hash-utils');
const { crackHash } = require('./hash-cracker');

const defaultHeaders = {
  'Content-Type': 'application/json',
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS'
};

exports.handler = async function(event, context) {
  // Handle CORS preflight
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 200, headers: defaultHeaders, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return {
      statusCode: 405,
      headers: defaultHeaders,
      body: JSON.stringify({ error: 'Method Not Allowed' })
    };
  }

  try {
    const body = JSON.parse(event.body || '{}');
    const { hash, crack = false } = body;

    if (!hash) {
      return {
        statusCode: 400,
        headers: defaultHeaders,
        body: JSON.stringify({ error: 'Hash is required' })
      };
    }

    const hashType = identifyHash(hash);
    const info = hashInfo[hashType] || { hashcat: '-', john: '-' };

    let result = { hash, type: hashType, ...info };

    // If cracking is requested, attempt to crack the hash
    if (crack) {
      try {
        const crackResult = await crackHash(hash, hashType);
        result.crack = crackResult;
      } catch (crackError) {
        console.error('Cracking error:', crackError);
        result.crack = {
          cracked: false,
          method: 'error',
          message: 'Error occurred during cracking attempt',
          timeElapsed: 0
        };
      }
    }

    return {
      statusCode: 200,
      headers: defaultHeaders,
      body: JSON.stringify(result)
    };
  } catch (error) {
    console.error('identify-hash error:', error);
    return {
      statusCode: 500,
      headers: defaultHeaders,
      body: JSON.stringify({ error: 'Internal Server Error', message: error.message })
    };
  }
};
