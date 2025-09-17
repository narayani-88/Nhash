const { hashInfo, identifyHash } = require('./hash-utils');

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
    const { hash } = body;

    if (!hash) {
      return {
        statusCode: 400,
        headers: defaultHeaders,
        body: JSON.stringify({ error: 'Hash is required' })
      };
    }

    const hashType = identifyHash(hash);
    const info = hashInfo[hashType] || { hashcat: '-', john: '-' };

    return {
      statusCode: 200,
      headers: defaultHeaders,
      body: JSON.stringify({ hash, type: hashType, ...info })
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
